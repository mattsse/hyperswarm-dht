//! Make RPC calls over a Kademlia based DHT.

use std::borrow::Borrow;
use std::collections::{HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::hash::Hash;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::time::Duration;

use async_std::net::UdpSocket;
use ed25519_dalek::{PublicKey, PUBLIC_KEY_LENGTH};
use futures::{
    stream::Stream,
    task::{Context, Poll},
};
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use wasm_timer::Instant;

pub use crate::rpc::message::*;
use crate::rpc::query::CommandQueryResponse;
use crate::{
    kbucket::{self, Entry, KBucketsTable, Key, KeyBytes, NodeStatus, K_VALUE},
    peers::PeersEncoding,
    rpc::{
        io::{IoConfig, IoHandler, IoHandlerEvent, MessageEvent, VERSION},
        jobs::PeriodicJob,
        query::{
            table::PeerState, CommandQuery, QueryConfig, QueryEvent, QueryId, QueryPool,
            QueryPoolState, QueryStats, QueryStream, QueryType,
        },
    },
};

pub mod io;
mod jobs;
pub mod message;
pub mod protocol;
pub mod query;
pub mod udp;

pub struct RpcDht {
    /// Identifier of this node
    id: Key<IdBytes>,
    // TODO change Key to Key<PeerId>
    kbuckets: KBucketsTable<Key<IdBytes>, Node>,
    io: IoHandler<QueryId>,
    bootstrap_job: PeriodicJob,
    ping_job: PeriodicJob,
    /// The currently active (i.e. in-progress) queries.
    queries: QueryPool,
    /// Custom commands
    // TODO support custom encoding?
    commands: HashSet<String>,
    /// Queued events to return when being polled.
    queued_events: VecDeque<RpcDhtEvent>,
    /// Nodes to bootstrap from
    bootstrap_nodes: Vec<SocketAddr>,
    bootstrapped: bool,
}

#[derive(Debug)]
pub struct DhtConfig {
    kbucket_pending_timeout: Duration,
    local_id: Option<IdBytes>,
    commands: HashSet<String>,
    query_config: QueryConfig,
    io_config: IoConfig,
    bootstrap_interval: Duration,
    ping_interval: Duration,
    connection_idle_timeout: Duration,
    ephemeral: bool,
    pub(crate) adaptive: bool,
    bootstrap_nodes: Option<Vec<SocketAddr>>,
    socket: Option<UdpSocket>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        DhtConfig {
            kbucket_pending_timeout: Duration::from_secs(60),
            local_id: None,
            commands: Default::default(),
            query_config: Default::default(),
            ping_interval: Duration::from_secs(40),
            bootstrap_interval: Duration::from_secs(320),
            connection_idle_timeout: Duration::from_secs(10),
            ephemeral: false,
            adaptive: false,
            bootstrap_nodes: None,
            socket: None,
            io_config: Default::default(),
        }
    }
}

impl DhtConfig {
    /// Set the id used to sign the messages explicitly.
    pub fn set_local_id(mut self, id: impl Into<IdBytes>) -> Self {
        self.local_id = Some(id.into());
        self
    }

    /// Use an existing UDP socket.
    pub fn set_socket(mut self, socket: UdpSocket) -> Self {
        self.socket = Some(socket);
        self
    }

    /// Create a new UDP socket and attempt to bind it to the addr provided.
    pub async fn bind<A: async_std::net::ToSocketAddrs>(
        mut self,
        addr: A,
    ) -> Result<Self, (Self, std::io::Error)> {
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                self.socket = Some(socket);
                Ok(self)
            }
            Err(err) => Err((self, err)),
        }
    }

    /// Set the secret keys to create roundtrip tokens
    pub fn set_secrets(mut self, secrets: ([u8; 32], [u8; 32])) -> Self {
        self.io_config.secrets = Some(secrets);
        self
    }

    /// Set the key rotation interval to rotate the keys used to create roundtrip tokens
    pub fn set_key_rotation_interval(mut self, rotation: Duration) -> Self {
        self.io_config.rotation = Some(rotation);
        self
    }

    /// Sets the timeout for a single query.
    ///
    /// > **Note**: A single query usually comprises at least as many requests
    /// > as the replication factor, i.e. this is not a request timeout.
    ///
    /// The default is 60 seconds.
    pub fn set_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_config.timeout = timeout;
        self
    }

    /// Sets the replication factor to use.
    ///
    /// The replication factor determines to how many closest peers
    /// a record is replicated. The default is [`K_VALUE`].
    pub fn set_replication_factor(mut self, replication_factor: NonZeroUsize) -> Self {
        self.query_config.replication_factor = replication_factor;
        self
    }

    /// Sets the allowed level of parallelism for iterative queries.
    ///
    /// The `α` parameter in the Kademlia paper. The maximum number of peers
    /// that an iterative query is allowed to wait for in parallel while
    /// iterating towards the closest nodes to a target. Defaults to
    /// `ALPHA_VALUE`.
    ///
    /// This only controls the level of parallelism of an iterative query, not
    /// the level of parallelism of a query to a fixed set of peers.
    ///
    /// When used with [`KademliaConfig::disjoint_query_paths`] it equals
    /// the amount of disjoint paths used.
    pub fn set_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
        self.query_config.parallelism = parallelism;
        self
    }

    /// Sets the (re-)replication interval for `bootstrap` query.
    pub fn bootstrap_interval(mut self, interval: Duration) -> Self {
        self.bootstrap_interval = interval;
        self
    }

    /// Register all commands to listen to.
    pub fn register_commands<T, I>(mut self, cmds: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        for cmd in cmds.into_iter() {
            self.commands.insert(cmd.to_string());
        }
        self
    }

    /// Sets interval for a `ping` query.
    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Set ephemeral: true so other peers do not add us to the peer list, simply bootstrap.
    ///
    /// An ephemeral dht node won't expose its id to remote peers, hence being ignored.
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    pub fn adaptive(mut self) -> Self {
        self.adaptive = true;
        self
    }

    pub fn empty_bootstrap_nodes(mut self) -> Self {
        self.bootstrap_nodes = Some(vec![]);
        self
    }

    /// Set the nodes to bootstrap from
    pub fn set_bootstrap_nodes<T: ToSocketAddrs>(mut self, addresses: &[T]) -> Self {
        let mut bootstrap_nodes = vec![];

        for addrs in addresses {
            if let Ok(addrs) = addrs.to_socket_addrs() {
                for addr in addrs {
                    bootstrap_nodes.push(addr)
                }
            }
        }
        self.bootstrap_nodes = Some(bootstrap_nodes);
        self
    }

    pub fn bootstrap_nodes(&mut self) -> Option<&mut Vec<SocketAddr>> {
        self.bootstrap_nodes.as_mut()
    }
}

impl RpcDht {
    /// Creates a new `Dht` network behaviour with the given configuration.
    ///
    /// If no socket was created within then `DhtConfig`, a new socket at a random port will be created.
    pub async fn with_config(config: DhtConfig) -> std::io::Result<Self> {
        let local_id = Key::new(config.local_id.unwrap_or_else(IdBytes::random));

        let query_id = if config.ephemeral {
            None
        } else {
            Some(local_id.clone())
        };

        let socket = if let Some(socket) = config.socket {
            socket
        } else {
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                0,
            )))
            .await?
        };

        let io = IoHandler::new(query_id, socket, config.io_config);

        let mut dht = Self {
            id: local_id.clone(),
            kbuckets: KBucketsTable::new(local_id.clone(), config.kbucket_pending_timeout),
            io,
            bootstrap_job: PeriodicJob::new(config.bootstrap_interval),
            ping_job: PeriodicJob::new(config.ping_interval),
            queries: QueryPool::new(local_id, config.query_config),
            commands: config.commands,
            queued_events: Default::default(),
            bootstrap_nodes: config.bootstrap_nodes.unwrap_or_default(),
            bootstrapped: false,
        };

        dht.bootstrap();
        Ok(dht)
    }

    /// Whether this a ephemeral node.
    ///
    /// Ephemeral nodes are short-lived and not added to the routing table.
    #[inline]
    pub fn is_ephemeral(&self) -> bool {
        self.io.is_ephemeral()
    }

    #[inline]
    pub fn bootstrap(&mut self) {
        if !self.bootstrap_nodes.is_empty() {
            self.query(Command::FindNode, self.id.clone(), None);
        } else {
            if !self.bootstrapped {
                self.queued_events.push_back(RpcDhtEvent::Bootstrapped {
                    stats: QueryStats::empty(),
                });
                self.bootstrapped = true;
            }
        }
    }

    /// The registered custom commands this node supports.
    #[inline]
    pub fn commands(&self) -> &HashSet<String> {
        &self.commands
    }

    #[inline]
    pub fn commands_mut(&mut self) -> &mut HashSet<String> {
        &mut self.commands
    }

    /// Add an additional command to the supported command list.
    ///
    /// Messages related to additional commands will be available as a [`CustomCommandRequest`] event.
    #[inline]
    pub fn register_command(&mut self, cmd: impl ToString) -> bool {
        self.commands.insert(cmd.to_string())
    }

    /// Returns the local address that this listener is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    /// Returns the id used to identify this node.
    #[inline]
    pub fn local_id(&self) -> &IdBytes {
        self.id.preimage()
    }

    /// Ping a remote
    pub fn ping(&mut self, peer: &PeerId) {
        self.io.query(
            Command::Ping,
            None,
            Some(peer.id.clone().to_vec()),
            Peer::from(peer.addr),
            // TODO refactor ping handling, no query id required
            self.queries.next_query_id(),
        )
    }

    fn ping_some(&mut self) {
        let cnt = if self.queries.len() > 2 { 3 } else { 5 };
        let now = Instant::now();
        for peer in self
            .kbuckets
            .iter()
            .filter_map(|entry| {
                if now > entry.node.value.next_ping {
                    Some(PeerId::new(
                        entry.node.value.addr,
                        entry.node.key.preimage().clone(),
                    ))
                } else {
                    None
                }
            })
            .take(cnt)
            .collect::<Vec<_>>()
        {
            self.ping(&peer)
        }
    }

    fn reping(&mut self) {}

    pub fn query_and_update(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<IdBytes>,
        value: Option<Vec<u8>>,
    ) -> QueryId {
        self.run_command(cmd, target, value, QueryType::QueryUpdate)
    }

    fn run_command(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<IdBytes>,
        value: Option<Vec<u8>>,
        query_type: QueryType,
    ) -> QueryId {
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
        )
    }

    pub fn holepunch(&mut self, peer: Peer) -> bool {
        if peer.referrer.is_some() {
            let id = self.queries.next_query_id();
            self.io.query(Command::Holepunch, None, None, peer, id);
            true
        } else {
            false
        }
    }

    pub fn query(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<IdBytes>,
        value: Option<Vec<u8>>,
    ) -> QueryId {
        self.run_command(cmd, target, value, QueryType::Query)
    }

    pub fn update(
        &mut self,
        cmd: impl Into<Command>,
        target: Key<IdBytes>,
        value: Option<Vec<u8>>,
    ) -> QueryId {
        self.run_command(cmd, target, value, QueryType::Update)
    }

    fn add_node(
        &mut self,
        id: IdBytes,
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
        to: Option<SocketAddr>,
    ) {
        let key = kbucket::Key::new(id);
        match self.kbuckets.entry(&key) {
            Entry::Present(mut entry, _) => {
                entry.value().next_ping = Instant::now() + self.ping_job.interval;
            }
            Entry::Pending(mut entry, _) => {
                let n = entry.value();
                n.addr = peer.addr;
                n.next_ping = Instant::now() + self.ping_job.interval;
            }
            Entry::Absent(entry) => {
                let node = Node {
                    addr: peer.addr,
                    roundtrip_token,
                    to,
                    next_ping: Instant::now() + self.ping_job.interval,
                    referrers: vec![],
                };

                match entry.insert(node, NodeStatus::Connected) {
                    kbucket::InsertResult::Inserted => {
                        self.queued_events.push_back(RpcDhtEvent::RoutingUpdated {
                            peer,
                            old_peer: None,
                        });
                    }
                    kbucket::InsertResult::Full => {
                        log::debug!("Bucket full. Peer not added to routing table: {:?}", peer)
                    }
                    kbucket::InsertResult::Pending { disconnected: _ } => {

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
        key: &Key<IdBytes>,
    ) -> Option<kbucket::EntryView<kbucket::Key<IdBytes>, Node>> {
        match self.kbuckets.entry(key) {
            kbucket::Entry::Present(entry, _) => Some(entry.remove()),
            kbucket::Entry::Pending(entry, _) => Some(entry.remove()),
            kbucket::Entry::Absent(..) | kbucket::Entry::SelfEntry => None,
        }
    }

    fn remove_node(
        &mut self,
        peer: &Peer,
    ) -> Option<kbucket::EntryView<kbucket::Key<IdBytes>, Node>> {
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
            self.remove_peer(&id)
        } else {
            None
        }
    }

    /// Handle a response for our Ping command
    fn on_pong(&mut self, msg: Message, peer: Peer) {
        if let Some(id) = msg.valid_id_bytes() {
            match self.kbuckets.entry(&Key::new(id)) {
                Entry::Present(mut entry, _) => {
                    entry.value().next_ping = Instant::now() + self.ping_job.interval;
                    self.queued_events.push_back(RpcDhtEvent::ResponseResult(Ok(
                        ResponseOk::Pong(Peer::from(entry.value().addr)),
                    )));
                    return;
                }
                Entry::Pending(mut entry, _) => {
                    entry.value().next_ping = Instant::now() + self.ping_job.interval;
                    self.queued_events.push_back(RpcDhtEvent::ResponseResult(Ok(
                        ResponseOk::Pong(Peer::from(entry.value().addr)),
                    )));
                    return;
                }
                _ => {}
            }
        }

        self.queued_events
            .push_back(RpcDhtEvent::ResponseResult(Err(
                ResponseError::InvalidPong(peer),
            )))
    }

    /// Process a response.
    fn on_response(&mut self, req: Box<Message>, resp: Message, peer: Peer, id: QueryId) {
        if req.is_ping() {
            self.on_pong(resp, peer);
            return;
        }

        if let Some(query) = self.queries.get_mut(&id) {
            if let Some(resp) = query.inject_response(resp, peer) {
                self.queued_events
                    .push_back(RpcDhtEvent::ResponseResult(Ok(ResponseOk::Response(resp))))
            }
        }
    }

    /// Handle a custom command request.
    ///
    /// # Note
    ///
    /// This only checks if this custom `command` query is currently registered, but does not reply. Instead the incoming query is delegated to via [`Stream::poll`] as [`CommandQuery`] in [`RpcDhtEvent::RequestResult::RequestOk::CustomCommandRequest`].
    /// It it the command's registrar's responsibility to process this query and eventually reply.
    fn on_command_req(&mut self, ty: Type, command: String, msg: Message, peer: Peer) {
        if let Some(target) = msg.valid_target_id_bytes() {
            if self.commands.contains(&command) {
                let query = CommandQuery {
                    rid: msg.get_request_id(),
                    ty,
                    command,
                    peer,
                    target,
                    value: msg.value,
                };
                self.queued_events.push_back(RpcDhtEvent::RequestResult(Ok(
                    RequestOk::CustomCommandRequest { query },
                )));
            } else {
                self.queued_events.push_back(RpcDhtEvent::RequestResult(Err(
                    RequestError::UnsupportedCommand { command, msg, peer },
                )));
            }
        } else {
            self.queued_events.push_back(RpcDhtEvent::RequestResult(Err(
                RequestError::MissingTarget { msg, peer },
            )));
        }
    }

    /// Handle an incoming request.
    ///
    /// Eventually send a response.
    fn on_request(&mut self, mut msg: Message, peer: Peer, ty: Type) {
        if let Some(id) = msg.valid_id_bytes() {
            self.add_node(id, peer.clone(), None, msg.decode_to_peer());
        }

        if let Some(cmd) = msg.get_command() {
            match cmd {
                Command::Ping => self.on_ping(msg, peer),
                Command::FindNode => self.on_findnode(msg, peer),
                Command::Holepunch => self.on_holepunch(msg, peer),
                Command::Unknown(s) => self.on_command_req(ty, s, msg, peer),
            };
        } else {
            // TODO refactor with oncommand fn
            if msg.target.is_none() {
                self.queued_events.push_back(RpcDhtEvent::RequestResult(Err(
                    RequestError::MissingTarget { peer, msg },
                )));
                return;
            }
            if let Some(key) = msg.valid_target_id_bytes() {
                msg.error = Some("Unsupported command".to_string());
                self.reply(msg, peer.clone(), key);
            }
            self.queued_events.push_back(RpcDhtEvent::RequestResult(Err(
                RequestError::MissingCommand { peer },
            )));
        }
    }

    /// Handle a ping request
    fn on_ping(&mut self, msg: Message, peer: Peer) {
        if let Some(ref val) = msg.value {
            if self.id.preimage() != val {
                // ping wasn't meant for this node
                self.queued_events.push_back(RpcDhtEvent::RequestResult(Err(
                    RequestError::InvalidValue { peer, msg },
                )));
                return;
            }
        }
        self.io.response(msg, Some(peer.encode()), None, peer);
    }

    /// Handle an incoming find peers request.
    ///
    /// Reply only if the remote provided a target to get the closest nodes for.
    fn on_findnode(&mut self, msg: Message, peer: Peer) {
        if let Some(key) = msg.valid_target_id_bytes() {
            let closer_nodes = self.closer_nodes(key, usize::from(K_VALUE));
            self.io.response(msg, None, Some(closer_nodes), peer);
        }
    }

    fn on_holepunch(&mut self, mut msg: Message, mut peer: Peer) {
        if let Some(value) = msg.decode_holepunch() {
            if value.to.is_some() {
                if let Some(to) = value.decode_to_peer() {
                    if to == peer.addr {
                        // don't forward to self
                        return;
                    }
                    msg.version = Some(VERSION);
                    msg.id = self.io.msg_id();
                    msg.to = Some(to.encode());
                    msg.set_holepunch(&Holepunch::with_from(peer.encode()));
                    self.io.send_message(MessageEvent::Response { msg, peer });
                    return;
                } else {
                    return;
                }
            }
            if let Some(from) = value.decode_from_peer() {
                peer = Peer::from(from)
            }
            self.io.response(msg, None, None, peer)
        }
    }

    /// Reply to a custom command query.
    pub fn reply_command(&mut self, resp: impl Into<CommandQueryResponse>) {
        let resp = resp.into();
        self.reply(resp.msg, resp.peer, resp.target)
    }

    fn reply(&mut self, mut msg: Message, peer: Peer, key: IdBytes) {
        msg.closer_nodes = Some(self.closer_nodes(key, usize::from(K_VALUE)));
        if msg.error.is_some() {
            let _ = msg.value.take();
        }
        self.io.reply(msg, peer)
    }

    /// Get the `num` closest nodes in the bucket.
    fn closer_nodes(&mut self, key: IdBytes, num: usize) -> Vec<u8> {
        let nodes = self
            .kbuckets
            .closest(&KeyBytes::new(key))
            .take(num)
            .collect::<Vec<_>>();
        PeersEncoding::encode(&nodes)
    }

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
            IoHandlerEvent::InResponseBadRequestId { peer, .. } => {
                // received a response that did not match any issued requests
                self.remove_node(&peer);
            }
            IoHandlerEvent::OutRequest { .. } => {
                // sent a request
            }
            IoHandlerEvent::InResponse {
                req,
                resp,
                peer,
                user_data,
            } => {
                self.on_response(req, resp, peer, user_data);
            }
            IoHandlerEvent::RequestTimeout {
                msg: _,
                peer,
                sent: _,
                user_data,
            } => {
                if let Some(query) = self.queries.get_mut(&user_data) {
                    query.on_timeout(peer);
                }
            }
        }
    }

    /// Delegate new query event to the io handler
    fn inject_query_event(&mut self, id: QueryId, event: QueryEvent) {
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
                self.remove_peer(&Key::new(id));
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
    }

    /// Handles a finished query.
    fn query_finished(&mut self, query: QueryStream) -> Option<RpcDhtEvent> {
        let is_find_node = query.command().is_find_node();

        let result = query.into_result();

        // add nodes to the table
        for (peer, state) in result.peers {
            match state {
                PeerState::Failed => {
                    self.remove_peer(&Key::new(peer.id));
                }
                PeerState::Succeeded {
                    roundtrip_token,
                    to,
                } => {
                    self.add_node(peer.id, Peer::from(peer.addr), Some(roundtrip_token), to);
                }
                _ => {}
            }
        }

        // first `find_node` query is issued as bootstrap
        if is_find_node {
            if !self.bootstrapped {
                self.bootstrapped = true;
                return Some(RpcDhtEvent::Bootstrapped {
                    stats: result.stats,
                });
            }
        }

        Some(RpcDhtEvent::QueryResult {
            id: result.inner,
            cmd: result.cmd,
            stats: result.stats,
        })
    }

    /// Handles a query that timed out.
    fn query_timeout(&mut self, query: QueryStream) -> Option<RpcDhtEvent> {
        self.query_finished(query)
    }
}

impl Stream for RpcDht {
    type Item = RpcDhtEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        let now = Instant::now();

        if let Poll::Ready(()) = pin.bootstrap_job.poll(cx, now) {
            if pin.kbuckets.iter().count() < 20 {
                pin.bootstrap();
            }
        }

        if let Poll::Ready(()) = pin.ping_job.poll(cx, now) {
            pin.ping_some()
        }

        loop {
            // Drain queued events first.
            if let Some(event) = pin.queued_events.pop_front() {
                return Poll::Ready(Some(event));
            }

            // Look for a sent/received message
            loop {
                if let Poll::Ready(Some(event)) = Stream::poll_next(Pin::new(&mut pin.io), cx) {
                    pin.inject_event(event);
                    if let Some(event) = pin.queued_events.pop_front() {
                        return Poll::Ready(Some(event));
                    }
                } else {
                    match pin.queries.poll(now) {
                        QueryPoolState::Waiting(Some((query, event))) => {
                            let id = query.id();
                            pin.inject_query_event(id, event);
                        }
                        QueryPoolState::Finished(q) => {
                            if let Some(event) = pin.query_finished(q) {
                                return Poll::Ready(Some(event));
                            }
                        }
                        QueryPoolState::Timeout(q) => {
                            if let Some(event) = pin.query_timeout(q) {
                                return Poll::Ready(Some(event));
                            }
                        }
                        QueryPoolState::Waiting(None) | QueryPoolState::Idle => {
                            break;
                        }
                    }
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

impl Into<Holepunch> for &Peer {
    fn into(self) -> Holepunch {
        Holepunch::with_from(self.encode())
    }
}

impl Into<Holepunch> for SocketAddr {
    fn into(self) -> Holepunch {
        let peer = Peer::from(self);
        (&peer).into()
    }
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct PeerId {
    pub addr: SocketAddr,
    pub id: IdBytes,
}

impl PeerId {
    fn new(addr: SocketAddr, id: IdBytes) -> Self {
        Self { addr, id }
    }
}

impl Borrow<[u8]> for PeerId {
    fn borrow(&self) -> &[u8] {
        self.id.borrow()
    }
}

/// A 32 byte identifier for a node participating in the DHT.
#[derive(Debug, Clone, Hash, PartialOrd, PartialEq, Eq)]
pub struct IdBytes(pub [u8; PUBLIC_KEY_LENGTH]);

impl IdBytes {
    /// Create new 32 byte array with random bytes.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        fill_random_bytes(&mut key);
        Self(key)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PartialEq<Vec<u8>> for IdBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0[..] == other.as_slice()
    }
}

impl Borrow<[u8]> for IdBytes {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for IdBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&PublicKey> for IdBytes {
    fn from(key: &PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<&GenericArray<u8, U32>> for IdBytes {
    fn from(digest: &GenericArray<u8, U32>) -> Self {
        Self(digest.as_slice().try_into().expect("Wrong length"))
    }
}

impl From<[u8; 32]> for IdBytes {
    fn from(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl TryFrom<&[u8]> for IdBytes {
    type Error = std::array::TryFromSliceError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(buf.try_into()?))
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
    /// When a new ping is due
    pub next_ping: Instant,
    /// Known referrers available for holepunching
    pub referrers: Vec<SocketAddr>,
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

/// Response received from `peer` to a request submitted by this DHT.
#[derive(Debug, Clone)]
pub struct Response {
    /// The id of the associated query
    pub query: QueryId,
    /// Command of the response message
    pub cmd: Command,
    /// How the request was initiated, as query, update or both.
    pub ty: QueryType,
    /// `to` field of the message
    pub to: Option<SocketAddr>,
    /// Peer that issued this reponse
    pub peer: SocketAddr,
    /// Included identifier of the peer.
    pub peer_id: Option<IdBytes>,
    /// response payload
    pub value: Option<Vec<u8>>,
}

/// Unique identifier for a request. Must be passed back in order to answer a request from
/// the remote.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(pub(crate) u64);

#[derive(Debug)]
pub enum RpcDhtEvent {
    /// Result for an incoming request
    RequestResult(RequestResult),
    /// Result for an incoming response
    ResponseResult(ResponseResult),
    /// The routing table has been updated.
    RoutingUpdated {
        /// The ID of the peer that was added or updated.
        peer: Peer,
        /// The ID of the peer that was evicted from the routing table to make
        /// room for the new peer, if any.
        old_peer: Option<PeerId>,
    },
    Bootstrapped {
        /// Execution statistics from the bootstrap query.
        stats: QueryStats,
    },
    /// A completed query.
    ///
    /// No more responses are expected for this query
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

#[derive(Debug)]
pub enum RequestOk {
    /// Custom incoming request to a registered command
    ///
    /// # Note
    ///
    /// Custom commands are not automatically replied to and need to be answered manually
    CustomCommandRequest {
        /// The query we received and need to respond to
        query: CommandQuery,
    },
}

#[derive(Debug)]
pub enum RequestError {
    /// Received a query with a custom command that is not registered
    UnsupportedCommand {
        /// The unknown command
        command: String,
        /// The message we received from the peer.
        msg: Message,
        /// The peer the message originated from.
        peer: Peer,
    },
    /// The `target` field of message was required but was empty
    MissingTarget { msg: Message, peer: Peer },
    /// Received a message with a type other than [`Type::Query`], [`Type::Response`], [`Type::Update`]
    InvalidType { ty: i32, msg: Message, peer: Peer },
    /// Received a request with no command attached.
    MissingCommand { peer: Peer },
    /// Ignored Request due to message's value being this peer's id.
    InvalidValue { msg: Message, peer: Peer },
}

pub type ResponseResult = Result<ResponseOk, ResponseError>;

#[derive(Debug)]
pub enum ResponseOk {
    /// Received a pong response to our ping request.
    Pong(Peer),
    /// A remote peer successfully responded to our query
    Response(Response),
}

#[derive(Debug)]
pub enum ResponseError {
    /// We received a bad pong to our ping request
    InvalidPong(Peer),
}

pub struct ResponseBuilder {}

impl ResponseBuilder {
    pub fn into_error(self, _err: impl Into<String>) {}

    pub fn into_resp(self, _value: Vec<u8>) {}
}

#[inline]
pub(crate) fn fill_random_bytes(dest: &mut [u8]) {
    use rand::SeedableRng;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore,
    };
    let mut rng = StdRng::from_rng(OsRng::default()).unwrap();
    rng.fill_bytes(dest)
}
