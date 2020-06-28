//! Make RPC calls over a Kademlia based DHT.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::pin::Pin;

use futures::pin_mut;
use futures::task::{Context, Poll};
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use tokio::stream::Stream;

use crate::rpc::io::RpcEvent;
use crate::rpc::message::Type;
use crate::{
    kbucket::{self, KBucketsTable, KeyBytes},
    peers::{PeersCodec, PeersEncoding},
    rpc::io::Io,
    rpc::message::{Command, CommandCodec, Message},
};

pub mod io;
pub mod message;
pub mod protocol;
pub mod query;

pub struct DHT {
    id: GenericArray<u8, U32>,
    query_id: Option<KeyBytes>,
    // TODO change socketAddr to IpV4?
    kbuckets: KBucketsTable<kbucket::Key<GenericArray<u8, U32>>, SocketAddr>,
    ephemeral: bool,
    io: Io,
    /// Commands for custom value encoding/decoding
    commands: HashMap<String, Box<dyn CommandCodec>>,
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

    pub fn query_and_update(&mut self) {
        unimplemented!()
    }

    fn add_node(&mut self, id: &[u8], peer: Peer, token: Option<Vec<u8>>, to: Option<Vec<u8>>) {
        unimplemented!()
    }

    fn remove_node(&mut self) {
        unimplemented!()
    }

    fn run_command(&mut self) {
        unimplemented!()
    }

    fn onresponse(&mut self, msg: Message, peer: Peer) {
        if let Some(id) = msg.valid_id() {
            self.add_node(id, peer, msg.roundtrip_token.clone(), msg.to.clone());
        }
    }

    fn oncommand(&mut self, ty: Type, cmd: String, msg: Message, peer: Peer) -> CommandResult {
        if msg.target.is_none() {
            return Err(CommandError::MissingTarget);
        }
        if let Some(cmd) = self.commands.get(&cmd) {
            // TODO encoding/decoding + reply
            unimplemented!()
        } else {
            Err(CommandError::UnsupportedCommand(cmd))
        }
    }

    fn onrequest(&mut self, ty: Type, msg: Message, peer: Peer) -> CommandResult {
        if let Some(id) = msg.valid_id() {
            self.add_node(id, peer.clone(), None, msg.to.clone());
        }

        if let Some(cmd) = msg.get_command() {
            match cmd {
                Command::Ping => self.onping(msg, peer),
                Command::FindNode => self.onfindnode(msg, peer),
                Command::HolePunch => self.onholepunch(msg, peer),
                Command::Unknown(s) => self.oncommand(ty, s, msg, peer),
            }
        } else {
            // TODO reply_error
            Err(CommandError::MissingCommand)
        }
    }

    fn onping(&mut self, msg: Message, peer: Peer) -> CommandResult {
        if let Some(ref val) = msg.value {
            if self.id.as_slice() == val.as_slice() {
                return Ok(());
            }
        }

        // TODO error handling
        self.io.response(msg, Some(peer.encode()), None, peer);

        Ok(())
    }

    fn onfindnode(&mut self, msg: Message, peer: Peer) -> CommandResult {
        if let Some(key) = msg.valid_key_bytes() {
            let closer_nodes = self.closer_nodes(&key, 20);
            // TODO error handling
            self.io.response(msg, None, Some(closer_nodes), peer);
        }

        Ok(())
    }

    fn onholepunch(&mut self, msg: Message, peer: Peer) -> CommandResult {
        unimplemented!()
    }

    fn reply_err(&mut self, error: String, value: Option<Vec<u8>>) {
        unimplemented!()
    }

    fn closer_nodes(&mut self, key: &KeyBytes, num: usize) -> Vec<u8> {
        let nodes = self.kbuckets.closest(key).take(20).collect::<Vec<_>>();
        PeersEncoding::encode(&nodes)
    }

    fn inject_event(&mut self, event: RpcEvent) {
        match event {
            RpcEvent::OutMessage { .. } => {}
            RpcEvent::OutSocketErr { .. } => {}
            RpcEvent::InMessage { msg, peer, ty } => match ty {
                Type::Query => {}
                Type::Update => {}
                Type::Response => {}
            },
            RpcEvent::InMessageErr { .. } => {}
            RpcEvent::InSocketErr { .. } => {}
            RpcEvent::InRequestBadId { .. } => {}
        }
    }
}

impl Stream for DHT {
    type Item = DhtEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        let io = &mut pin.io;
        pin_mut!(io);
        if let Poll::Ready(Some(event)) = Stream::poll_next(io, cx) {}

        // # Strategy
        // 1. poll IO
        // process io event
        // return dht event

        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    /// Referrer that told us about this node.
    pub referrer: Option<SocketAddr>,
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
    CommandResult(CommandResult),
}

pub type CommandResult = Result<(), CommandError>;

pub enum CommandError {
    UnsupportedCommand(String),
    MissingTarget,
    MissingCommand,
}
