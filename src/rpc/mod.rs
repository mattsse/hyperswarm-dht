//! Make RPC calls over a Kademlia based DHT.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::pin::Pin;

use futures::task::{Context, Poll};
use futures::{pin_mut, TryStreamExt};
use log::debug;
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use tokio::stream::Stream;

use crate::kbucket::{Entry, Key, NodeStatus};
use crate::peers::decode_peers;
use crate::rpc::io::RpcEvent;
use crate::rpc::message::Type;
use crate::rpc::query::Query;
use crate::{
    kbucket::{self, KBucketsTable, KeyBytes},
    peers::{PeersCodec, PeersEncoding},
    rpc::io::Io,
    rpc::message::{Command, CommandCodec, Message},
};
use bytes::{Bytes, BytesMut};
use fnv::FnvHashSet;

pub mod io;
pub mod message;
pub mod protocol;
pub mod query;

pub struct DHT {
    id: GenericArray<u8, U32>,
    query_id: Option<KeyBytes>,
    // TODO change socketAddr to IpV4?
    kbuckets: KBucketsTable<kbucket::Key<Vec<u8>>, Node>,
    ephemeral: bool,
    io: Io,
    /// The currently connected peers.
    ///
    /// This is a superset of the connected peers currently in the routing table.
    connected_peers: FnvHashSet<Vec<u8>>,
    /// Commands for custom value encoding/decoding
    commands: HashMap<String, Box<dyn CommandCodec>>,
    /// Queued events to return when being polled.
    queued_events: VecDeque<DhtEvent>,
}

impl DHT {
    pub fn bootstrap(&mut self) {
        unimplemented!()
    }

    #[inline]
    pub fn commands(&self) -> &HashMap<String, Box<dyn CommandCodec>> {
        &self.commands
    }

    #[inline]
    pub fn commands_mut(&mut self) -> &mut HashMap<String, Box<dyn CommandCodec>> {
        &mut self.commands
    }

    #[inline]
    pub fn address(&self) -> &SocketAddr {
        self.io.address()
    }

    /// Ping a remote
    pub fn ping(&mut self, peer: &Node) -> anyhow::Result<()> {
        self.io.query(
            Command::Ping,
            None,
            Some(peer.id.to_vec()),
            Peer::from(peer.addr),
        )
    }

    pub fn query_and_update(&mut self) {
        unimplemented!()
    }

    pub fn query(&mut self, cmd: impl Into<Command>) {
        unimplemented!()
    }

    fn add_node(
        &mut self,
        id: &[u8],
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
        to: Option<Vec<u8>>,
    ) {
        let id = id.to_vec();
        let key = kbucket::Key::new(id.clone());
        match self.kbuckets.entry(&key) {
            Entry::Present(_, _) => {}
            Entry::Pending(mut entry, _) => {
                let n = entry.value();
                n.id = id;
                n.addr = peer.addr;
            }
            Entry::Absent(entry) => {
                let status = if self.connected_peers.contains(&id) {
                    NodeStatus::Connected
                } else {
                    NodeStatus::Disconnected
                };

                let node = Node {
                    id,
                    addr: peer.addr,
                    roundtrip_token,
                    to,
                };

                match entry.insert(node, status) {
                    kbucket::InsertResult::Inserted => {
                        // self.queued_events.push_back(NetworkBehaviourAction::GenerateEvent(
                        //     KademliaEvent::RoutingUpdated {
                        //         peer: peer.clone(),
                        //         addresses,
                        //         old_peer: None,
                        //     }
                        // ));
                    }
                    kbucket::InsertResult::Full => {
                        debug!("Bucket full. Peer not added to routing table: {:?}", peer)
                    }
                    kbucket::InsertResult::Pending { disconnected } => {

                        // TODO dial remote
                    }
                }
            }
            Entry::SelfEntry => {}
        }
    }

    fn remove_node(&mut self, peer: Peer) {
        DhtEvent::RemovedBadIdNode(peer);
        unimplemented!()
    }

    fn run_command(&mut self) {
        unimplemented!()
    }

    /// Handle a response for our Ping command
    fn on_pong(&mut self, msg: &Message, peer: &Peer) {
        if let Some(to) = msg.to.as_ref().or(msg.value.as_ref()) {
            if let Some(addr) = decode_peers(to).into_iter().next() {
                self.queued_events
                    .push_back(DhtEvent::ResponseResult(Ok(ResponseOk::Pong(Peer::from(
                        addr,
                    )))));
                return;
            }
        }
        self.queued_events
            .push_back(DhtEvent::ResponseResult(Err(ResponseError::InvalidPong(
                peer.clone(),
            ))))
    }

    fn on_response(&mut self, msg: Message, peer: Peer) {
        // TODO match command
        if let Some(cmd) = msg.get_command() {
            match cmd {
                Command::Ping => self.on_pong(&msg, &peer),
                Command::FindNode => {}
                Command::HolePunch => {}
                Command::Unknown(_) => {}
            }
        }

        if let Some(id) = msg.valid_id() {
            self.connected_peers.insert(id.to_vec());
            // TODO self.connection_updated
            self.add_node(id, peer, msg.roundtrip_token.clone(), msg.to.clone());
        }
    }

    /// Handle a custom command request
    fn on_command(&mut self, ty: Type, command: String, msg: Message, peer: Peer) -> RequestResult {
        if msg.target.is_none() {
            return Err(RequestError::MissingTarget);
        }
        if let Some(cmd) = self.commands.get_mut(&command) {
            // apply custom cmd decoding
            let value = msg
                .value
                .as_ref()
                .map(|val| cmd.decode(&mut BytesMut::from(val.as_slice())))
                .map_or(Ok(None), |r| {
                    r.map(Some).map_err(|err| RequestError::QueryCodec(err))
                })?;

            let query = Query {
                ty,
                command,
                node: peer.clone(),
                target: msg.target.clone(),
                value: None,
            };

            let res = if ty == Type::Update {
                cmd.update(&query)
            } else {
                cmd.query(&query)
            }
            .map(|val| {
                val.map(|val| {
                    let mut bytes = BytesMut::with_capacity(val.len());
                    // TODO error handling
                    cmd.encode(val, &mut bytes);
                    bytes.to_vec()
                })
            });

            if let Some(keys) = msg.valid_target_key_bytes() {
                self.reply(msg, peer, res, &keys)
            } else {
                Err(RequestError::MissingTarget)
            }
        } else {
            Err(RequestError::UnsupportedCommand(command))
        }
    }

    /// Handle an incoming request
    fn on_request(&mut self, msg: Message, peer: Peer) -> RequestResult {
        let ty = msg.get_type().map_err(|i| RequestError::InvalidType(i))?;

        if let Some(id) = msg.valid_id() {
            self.add_node(id, peer.clone(), None, msg.to.clone());
        }

        if let Some(cmd) = msg.get_command() {
            match cmd {
                Command::Ping => self.on_ping(msg, peer),
                Command::FindNode => self.on_findnode(msg, peer),
                Command::HolePunch => self.on_holepunch(msg, peer),
                Command::Unknown(s) => self.on_command(ty, s, msg, peer),
            }
        } else {
            // TODO refactor with oncommand fn
            if msg.target.is_none() {
                return Err(RequestError::MissingTarget);
            }
            if let Some(key) = msg.valid_target_key_bytes() {
                // TODO error handling
                self.reply(
                    msg,
                    peer.clone(),
                    Err("Unsupported command".to_string()),
                    &key,
                );
            }
            Err(RequestError::MissingCommand(peer))
        }
    }

    fn on_ping(&mut self, msg: Message, peer: Peer) -> RequestResult {
        if let Some(ref val) = msg.value {
            if self.id.as_slice() == val.as_slice() {
                return Ok(());
            }
        }

        // TODO error handling
        self.io.response(msg, Some(peer.encode()), None, peer);

        Ok(())
    }

    fn on_findnode(&mut self, msg: Message, peer: Peer) -> RequestResult {
        if let Some(key) = msg.valid_id_key_bytes() {
            let closer_nodes = self.closer_nodes(&key, 20);
            // TODO error handling
            self.io.response(msg, None, Some(closer_nodes), peer);
        }

        Ok(())
    }

    fn on_holepunch(&mut self, msg: Message, peer: Peer) -> RequestResult {
        unimplemented!()
    }

    fn reply(
        &mut self,
        msg: Message,
        peer: Peer,
        res: Result<Option<Vec<u8>>, String>,
        key: &KeyBytes,
    ) -> RequestResult {
        let closer_nodes = self.closer_nodes(key, 20);
        match res {
            Ok(value) => {
                self.io.response(msg, value, Some(closer_nodes), peer);
            }
            Err(err) => {
                self.io
                    .error(msg, Some(err), None, Some(closer_nodes), peer);
            }
        }
        Ok(())
    }

    fn closer_nodes(&mut self, key: &KeyBytes, num: usize) -> Vec<u8> {
        let nodes = self.kbuckets.closest(key).take(20).collect::<Vec<_>>();
        PeersEncoding::encode(&nodes)
    }

    fn inject_event(&mut self, event: RpcEvent) {
        match event {
            RpcEvent::OutResponse { .. } => {}
            RpcEvent::OutSocketErr { .. } => {}
            RpcEvent::InRequest { msg, peer } => {
                self.on_request(msg, peer);
            }
            RpcEvent::InMessageErr { .. } => {}
            RpcEvent::InSocketErr { .. } => {}
            RpcEvent::InResponseBadId { peer, .. } => {
                self.remove_node(peer);
            }
            RpcEvent::OutRequest { id: _ } => {}
            RpcEvent::InResponse { recv, sent, peer } => {
                // TODO match command
            }
            RpcEvent::RequestTimeout {
                msg: _,
                peer: _,
                sent: _,
            } => {}
        }
    }
}

impl Stream for DHT {
    type Item = DhtEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        // Drain queued events first.
        if let Some(event) = pin.queued_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        let io = &mut pin.io;
        pin_mut!(io);
        if let Poll::Ready(Some(event)) = Stream::poll_next(io, cx) {
            pin.inject_event(event)
        }

        // # Strategy
        // 1. poll IO
        // process io event
        // return dht event

        Poll::Pending
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Peer {
    pub addr: SocketAddr,
    /// Referrer that told us about this node.
    pub referrer: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct PeerId {
    pub addr: SocketAddr,
    pub id: GenericArray<u8, U32>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: Vec<u8>,
    pub addr: SocketAddr,
    pub roundtrip_token: Option<Vec<u8>>,
    pub to: Option<Vec<u8>>,
}

impl Peer {
    pub fn new(addr: SocketAddr, referrer: Option<SocketAddr>) -> Self {
        Self { addr, referrer }
    }
}

impl<T: Into<SocketAddr>> From<T> for Peer {
    fn from(s: T) -> Self {
        Self {
            addr: s.into(),
            referrer: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoundTripPeer {
    pub addr: SocketAddr,
    pub roundtrip_token: Vec<u8>,
}

/// Unique identifier for a request. Must be passed back in order to answer a request from
/// the remote.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(pub(crate) u64);

pub enum DhtEvent {
    RequestResult(RequestResult),
    ResponseResult(ResponseResult),
    RemovedBadIdNode(Peer),
}

pub type RequestResult = Result<(), RequestError>;

pub type ResponseResult = Result<ResponseOk, ResponseError>;

pub enum ResponseOk {
    Pong(Peer),
}

pub enum ResponseError {
    InvalidPong(Peer),
}

pub enum RequestError {
    UnsupportedCommand(String),
    MissingTarget,
    InvalidType(i32),
    MissingCommand(Peer),
    QueryCodec(std::io::Error),
}
