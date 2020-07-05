//! Make RPC calls over a Kademlia based DHT.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::pin::Pin;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use fnv::FnvHashSet;
use futures::{
    pin_mut,
    stream::Stream,
    task::{Context, Poll},
    TryStreamExt,
};
use log::debug;
use sha2::digest::generic_array::{typenum::U32, GenericArray};

use crate::kbucket::K_VALUE;
use crate::rpc::query::{QueryEvent, QueryPoolState, QueryStats, QueryStream, QueryType};
use crate::{
    kbucket::{self, KBucketsTable, KeyBytes},
    kbucket::{Entry, Key, NodeStatus},
    peers::decode_peers,
    peers::{PeersCodec, PeersEncoding},
    rpc::{
        io::{Io, IoHandlerEvent},
        message::Type,
        message::{Command, CommandCodec, Message},
        query::{QueryCommand, QueryId, QueryPool},
    },
};
use std::borrow::Borrow;
use wasm_timer::Instant;

pub mod io;
pub mod message;
pub mod protocol;
pub mod query;

pub struct DHT {
    id: Key<Vec<u8>>,
    query_id: Option<KeyBytes>,
    // TODO change Key to Key<PeerId>
    kbuckets: KBucketsTable<kbucket::Key<Vec<u8>>, Node>,
    ephemeral: bool,
    io: Io<QueryId>,
    ping_interval: Duration,

    /// The currently active (i.e. in-progress) queries.
    queries: QueryPool,

    /// The currently connected peers.
    ///
    /// This is a superset of the connected peers currently in the routing table.
    connected_peers: FnvHashSet<Vec<u8>>,

    /// Custom commands
    // TODO support custom encoding?
    commands: HashSet<String>,

    /// Queued events to return when being polled.
    queued_events: VecDeque<DhtEvent>,

    /// Nodes to bootstrap from
    bootstrap_nodes: Vec<SocketAddr>,

    bootstrapped: bool,
}

impl DHT {
    pub fn bootstrap(&mut self) {
        if !self.bootstrap_nodes.is_empty() {
            self.query(Command::FindNode, self.id.clone(), None);
        }
        self.bootstrapped = true;
    }

    #[inline]
    pub fn commands(&self) -> &HashSet<String> {
        &self.commands
    }

    #[inline]
    pub fn commands_mut(&mut self) -> &mut HashSet<String> {
        &mut self.commands
    }

    #[inline]
    pub fn register_command(&mut self, cmd: impl ToString) -> bool {
        self.commands.insert(cmd.to_string())
    }

    #[inline]
    pub fn address(&self) -> &SocketAddr {
        self.io.address()
    }

    /// Ping a remote
    pub fn ping(&mut self, peer: &Node) -> anyhow::Result<()> {
        unimplemented!()
        // TODO submit query directly to io handler
        // self.io.query(
        //     Command::Ping,
        //     None,
        //     Some(peer.id.to_vec()),
        //     Peer::from(peer.addr),
        // )
    }

    fn reping(&mut self) {}

    pub fn query_and_update(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<Vec<u8>>,
        value: Option<Vec<u8>>,
    ) {
        self.run_command(cmd, target, value, QueryType::QueryUpdate)
    }

    fn run_command(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<Vec<u8>>,
        value: Option<Vec<u8>>,
        query_type: QueryType,
    ) {
        let peers = self
            .kbuckets
            .closest(&target)
            .take(usize::from(K_VALUE))
            .map(|e| PeerId::new(e.node.value.addr, e.node.key.preimage().clone()))
            .map(Key::new)
            .collect::<Vec<_>>();

        self.queries.add_stream(
            cmd,
            peers,
            query_type,
            target,
            value,
            self.bootstrap_nodes.iter().cloned().map(Peer::from),
        );
    }

    pub fn query(&mut self, cmd: impl Into<Command>, target: Key<Vec<u8>>, value: Option<Vec<u8>>) {
        self.run_command(cmd, target, value, QueryType::Query)
    }

    // TODO return query id to track?
    pub fn update(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<Vec<u8>>,
        value: Option<Vec<u8>>,
    ) {
        self.run_command(cmd, target, value, QueryType::Update)
    }

    fn add_node(
        &mut self,
        id: &[u8],
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
        to: Option<SocketAddr>,
    ) {
        let id = id.to_vec();
        let key = kbucket::Key::new(id);
        match self.kbuckets.entry(&key) {
            Entry::Present(_, _) => {}
            Entry::Pending(mut entry, _) => {
                let n = entry.value();
                n.addr = peer.addr;
            }
            Entry::Absent(entry) => {
                let status = if self.connected_peers.contains(key.preimage()) {
                    NodeStatus::Connected
                } else {
                    NodeStatus::Disconnected
                };

                let node = Node {
                    addr: peer.addr,
                    roundtrip_token,
                    to,
                };

                match entry.insert(node, status) {
                    kbucket::InsertResult::Inserted => {
                        self.queued_events.push_back(DhtEvent::RoutingUpdated {
                            peer: peer.clone(),
                            old_peer: None,
                        });
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

    /// Removes a peer from the routing table.
    ///
    /// Returns `None` if the peer was not in the routing table,
    /// not even pending insertion.
    pub fn remove_peer(
        &mut self,
        peer: Vec<u8>,
    ) -> Option<kbucket::EntryView<kbucket::Key<Vec<u8>>, Node>> {
        let key = kbucket::Key::new(peer);
        match self.kbuckets.entry(&key) {
            kbucket::Entry::Present(entry, _) => Some(entry.remove()),
            kbucket::Entry::Pending(entry, _) => Some(entry.remove()),
            kbucket::Entry::Absent(..) | kbucket::Entry::SelfEntry => None,
        }
    }

    fn remove_node(
        &mut self,
        peer: &Peer,
    ) -> Option<kbucket::EntryView<kbucket::Key<Vec<u8>>, Node>> {
        let id = self
            .kbuckets
            .iter()
            .filter_map(|e| {
                if e.node.value.addr == peer.addr {
                    Some(e.node.key.clone())
                } else {
                    None
                }
            })
            .next();

        if let Some(id) = id {
            self.remove_peer(id.into_preimage())
        } else {
            None
        }
    }

    /// Handle a response for our Ping command
    fn on_pong(&mut self, msg: Message, peer: Peer) {
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
                peer,
            ))))
    }

    fn on_response(&mut self, req: Message, resp: Message, peer: Peer, id: QueryId) {
        if req.is_ping() {
            self.on_pong(resp, peer);
            return;
        }

        if let Some(query) = self.queries.get_mut(&id) {
            if let Some(resp) = query.inject_response(resp, peer.clone()) {
                self.queued_events
                    .push_back(DhtEvent::ResponseResult(Ok(ResponseOk::Response(resp))))
            }
        }
    }

    /// Handle a custom command request
    fn on_command_req(
        &mut self,
        ty: Type,
        command: String,
        msg: Message,
        peer: Peer,
    ) -> RequestResult {
        if msg.target.is_none() {
            return Err(RequestError::MissingTarget { msg, peer });
        }
        if self.commands.contains(&command) {
            // let res = if ty == Type::Update {
            //     cmd.update(&query)
            // } else {
            //     cmd.query(&query)
            // }
            // .map(|val| {
            //     val.map(|val| {
            //         let mut bytes = BytesMut::with_capacity(val.len());
            //         cmd.encode(val, &mut bytes);
            //         bytes.to_vec()
            //     })
            // });

            if let Some(_) = msg.valid_target_key_bytes() {
                let query = QueryCommand {
                    ty,
                    command,
                    node: peer.clone(),
                    target: msg.target.clone(),
                    value: msg.value,
                };
                Ok(RequestOk::CustomCommandRequest { query })
            } else {
                Err(RequestError::MissingTarget { msg, peer })
            }
        } else {
            Err(RequestError::UnsupportedCommand { command, msg, peer })
        }
    }

    /// Handle an incoming request.
    ///
    /// Eventually send a response.
    fn on_request(&mut self, msg: Message, peer: Peer, ty: Type) {
        if let Some(id) = msg.valid_id() {
            self.add_node(id, peer.clone(), None, msg.decode_to_peer());
        }

        if let Some(cmd) = msg.get_command() {
            let res = match cmd {
                Command::Ping => self.on_ping(msg, peer),
                Command::FindNode => self.on_findnode(msg, peer),
                Command::HolePunch => self.on_holepunch(msg, peer),
                Command::Unknown(s) => self.on_command_req(ty, s, msg, peer),
            };
            self.queued_events.push_back(DhtEvent::RequestResult(res));
        } else {
            // TODO refactor with oncommand fn
            if msg.target.is_none() {
                self.queued_events.push_back(DhtEvent::RequestResult(Err(
                    RequestError::MissingTarget { peer, msg },
                )));
                return;
            }
            if let Some(key) = msg.valid_target_key_bytes() {
                self.reply(
                    msg,
                    peer.clone(),
                    Err("Unsupported command".to_string()),
                    &key,
                );
            }
            self.queued_events.push_back(DhtEvent::RequestResult(Err(
                RequestError::MissingCommand { peer },
            )));
        }
    }

    /// Handle a ping request
    fn on_ping(&mut self, msg: Message, peer: Peer) -> RequestResult {
        if let Some(ref val) = msg.value {
            if self.id.preimage() == val {
                // TODO handle
                return Err(RequestError::InvalidValue { peer, msg });
            }
        }

        self.io
            .response(msg, Some(peer.encode()), None, peer.clone());

        Ok(RequestOk::Responded { peer })
    }

    fn on_findnode(&mut self, msg: Message, peer: Peer) -> RequestResult {
        if let Some(key) = msg.valid_id_key_bytes() {
            let closer_nodes = self.closer_nodes(&key, 20);
            self.io
                .response(msg, None, Some(closer_nodes), peer.clone());
        }
        Ok(RequestOk::Responded { peer })
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
                self.io
                    .response(msg, value, Some(closer_nodes), peer.clone());
            }
            Err(err) => {
                self.io
                    .error(msg, Some(err), None, Some(closer_nodes), peer.clone());
            }
        }
        Ok(RequestOk::Responded { peer })
    }

    /// Get the `num` closest nodes in the bucket.
    fn closer_nodes(&mut self, key: &KeyBytes, num: usize) -> Vec<u8> {
        let nodes = self
            .kbuckets
            .closest(key)
            .take(usize::from(K_VALUE))
            .collect::<Vec<_>>();
        PeersEncoding::encode(&nodes)
    }

    fn inject_response(&mut self, req: Message, response: Message, peer: Peer) {}

    /// Handle the event generated from the underlying IO
    fn inject_event(&mut self, event: IoHandlerEvent<QueryId>) {
        match event {
            IoHandlerEvent::OutResponse { .. } => {}
            IoHandlerEvent::OutSocketErr { .. } => {}
            IoHandlerEvent::InRequest { msg, peer, ty } => {
                self.on_request(msg, peer, ty);
            }
            IoHandlerEvent::InMessageErr { .. } => {}
            IoHandlerEvent::InSocketErr { .. } => {}
            IoHandlerEvent::InResponseBadId { peer, .. } => {
                // a bad id was supplied in the response from the peer
                if self.remove_node(&peer).is_some() {
                    self.queued_events
                        .push_back(DhtEvent::RemovedBadIdNode(peer));
                }
            }
            IoHandlerEvent::OutRequest { .. } => {}
            IoHandlerEvent::InResponse {
                req,
                resp,
                peer,
                user_data,
            } => {
                self.on_response(req, resp, peer, user_data);
            }
            IoHandlerEvent::RequestTimeout {
                msg,
                peer,
                sent,
                user_data,
            } => {
                if let Some(query) = self.queries.get_mut(&user_data) {
                    query.on_timeout(peer);
                }
            }
        }
    }

    /// Delegate new query event to the io handler
    fn inject_query_event(&mut self, id: QueryId, event: QueryEvent) -> Option<DhtEvent> {
        match event {
            QueryEvent::Query {
                peer,
                command,
                target,
                value,
            } => {
                self.io.query(command, Some(target), value, peer, id);
            }
            QueryEvent::RemoveNode { id } => {
                self.remove_peer(id);
            }
            QueryEvent::MissingRoundtripToken { .. } => {
                // TODO
            }
            QueryEvent::Update {
                peer,
                command,
                target,
                value,
                token,
            } => {
                self.io
                    .update(command, Some(target), value, peer, token, id);
            }
        }
        None
    }

    /// Handles a finished (i.e. successful) query.
    fn query_finished(&mut self, query: QueryStream) -> Option<DhtEvent> {
        let result = query.into_result();

        // add nodes to the table
        for (peer, token, to) in result.peers {
            self.add_node(&peer.id, Peer::from(peer.addr), Some(token), to);
        }

        Some(DhtEvent::QueryResult {
            id: result.inner,
            cmd: result.cmd,
            stats: result.stats,
        })
    }

    /// Handles a query that timed out.
    fn query_timeout(&self, query: QueryStream) -> Option<DhtEvent> {
        unimplemented!()
    }
}

impl Stream for DHT {
    type Item = DhtEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        loop {
            // Drain queued events first.
            if let Some(event) = pin.queued_events.pop_front() {
                return Poll::Ready(Some(event));
            }

            // Look for a finished query.
            loop {
                match pin.queries.poll(Instant::now()) {
                    QueryPoolState::Waiting(Some((query, event))) => {
                        let id = query.id();
                        if let Some(event) = pin.inject_query_event(id, event) {
                            return Poll::Ready(Some(event));
                        }
                    }
                    QueryPoolState::Finished(q) => if let Some(event) = pin.query_finished(q) {},
                    QueryPoolState::Timeout(q) => {
                        if let Some(event) = pin.query_timeout(q) {
                            // TODO timeout failed remote
                            // return Async::Ready(NetworkBehaviourAction::GenerateEvent(event))
                        }
                    }
                    QueryPoolState::Waiting(None) | QueryPoolState::Idle => break,
                }
            }

            // Look for a sent/received message
            loop {
                let io = &mut pin.io;
                pin_mut!(io);
                match Stream::poll_next(io, cx) {
                    Poll::Ready(Some(event)) => pin.inject_event(event),
                    _ => break,
                }
            }

            // No immediate event was produced as a result of a finished query or socket.
            // If no new events have been queued either, signal `Pending` to
            // be polled again later.
            if pin.queued_events.is_empty() {
                return Poll::Pending;
            }
        }
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
    // TODO change to kbucket::Key?
    pub id: Vec<u8>,
}

impl PeerId {
    fn new(addr: SocketAddr, id: Vec<u8>) -> Self {
        Self { addr, id }
    }
}

impl Borrow<[u8]> for PeerId {
    fn borrow(&self) -> &[u8] {
        &self.id
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    /// Address of the peer.
    pub addr: SocketAddr,
    /// last roundtrip token in a req/resp exchanged with the peer
    pub roundtrip_token: Option<Vec<u8>>,
    /// Decoded address of the `to` message field
    pub to: Option<SocketAddr>,
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

#[derive(Debug)]
pub struct Response {
    query: QueryId,
    cmd: Command,
    to: Option<SocketAddr>,
    peer: PeerId,
    value: Option<Vec<u8>>,
}

/// Unique identifier for a request. Must be passed back in order to answer a request from
/// the remote.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(pub(crate) u64);

pub enum DhtEvent {
    RequestResult(RequestResult),
    ResponseResult(ResponseResult),
    RemovedBadIdNode(Peer),
    /// The routing table has been updated.
    RoutingUpdated {
        /// The ID of the peer that was added or updated.
        peer: Peer,
        /// The ID of the peer that was evicted from the routing table to make
        /// room for the new peer, if any.
        old_peer: Option<PeerId>,
    },
    QueryResult {
        /// The ID of the query that finished.
        id: QueryId,
        /// The command of the executed query.
        cmd: Command,
        /// Execution statistics from the query.
        stats: QueryStats,
    },
}

pub type RequestResult = Result<RequestOk, RequestError>;

pub enum RequestOk {
    Responded {
        peer: Peer,
    },
    /// Custom request to a registered command
    ///
    /// # Note
    ///
    /// Custom commands are not automatically replied to and need to be answered manually
    CustomCommandRequest {
        query: QueryCommand,
    },
}

pub enum RequestError {
    UnsupportedCommand {
        command: String,
        msg: Message,
        peer: Peer,
    },
    MissingTarget {
        msg: Message,
        peer: Peer,
    },
    InvalidType {
        ty: i32,
        msg: Message,
        peer: Peer,
    },
    MissingCommand {
        peer: Peer,
    },
    /// Ignore Request due to value being this peer's id
    InvalidValue {
        msg: Message,
        peer: Peer,
    },
}

pub type ResponseResult = Result<ResponseOk, ResponseError>;

pub enum ResponseOk {
    Pong(Peer),
    Response(Response),
}

pub enum ResponseError {
    InvalidPong(Peer),
}
