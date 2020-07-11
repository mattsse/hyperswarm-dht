use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use fnv::FnvHashMap;
use futures::task::Poll;
use log::debug;
use wasm_timer::Instant;

use crate::{
    kbucket::{Key, KeyBytes, ALPHA_VALUE, K_VALUE},
    rpc::{
        message::{Command, Message, Type},
        query::fixed::FixedPeersIter,
        query::peers::PeersIterState,
        query::table::{PeerState, QueryTable},
        Node, Peer, PeerId, RequestId, Response, ResponseResult,
    },
};

mod fixed;
mod peers;
pub mod table;

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to completion.
#[derive(Debug)]
pub struct QueryPool {
    local_id: Key<Vec<u8>>,
    queries: FnvHashMap<QueryId, QueryStream>,
    config: QueryConfig,
    next_id: usize,
}

/// The configuration for queries in a `QueryPool`.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Timeout of a single query.
    ///
    /// See [`crate::behaviour::KademliaConfig::set_query_timeout`] for details.
    pub timeout: Duration,

    /// The replication factor to use.
    ///
    /// See [`crate::behaviour::KademliaConfig::set_replication_factor`] for details.
    pub replication_factor: NonZeroUsize,

    /// Allowed level of parallelism for iterative queries.
    ///
    /// See [`crate::behaviour::KademliaConfig::set_parallelism`] for details.
    pub parallelism: NonZeroUsize,
}

impl Default for QueryConfig {
    fn default() -> Self {
        QueryConfig {
            timeout: Duration::from_secs(60),
            replication_factor: NonZeroUsize::new(K_VALUE.get()).expect("K_VALUE > 0"),
            parallelism: ALPHA_VALUE,
        }
    }
}

impl QueryPool {
    /// Creates a new `QueryPool` with the given configuration.
    pub fn new(local_id: Key<Vec<u8>>, config: QueryConfig) -> Self {
        Self {
            local_id,
            next_id: 0,
            config,
            queries: Default::default(),
        }
    }

    /// Returns an iterator over the queries in the pool.
    pub fn iter(&self) -> impl Iterator<Item = &QueryStream> {
        self.queries.values()
    }

    /// Gets the current size of the pool, i.e. the number of running queries.
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub(crate) fn next_query_id(&mut self) -> QueryId {
        let id = QueryId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Adds a query to the pool.
    pub fn add_stream<T, I, S>(
        &mut self,
        cmd: T,
        peers: I,
        query_type: QueryType,
        target: Key<Vec<u8>>,
        value: Option<Vec<u8>>,
        bootstrap: S,
    ) -> QueryId
    where
        T: Into<Command>,
        I: IntoIterator<Item = Key<PeerId>>,
        S: IntoIterator<Item = Peer>,
    {
        let id = self.next_query_id();
        let query = QueryStream::bootstrap(
            id,
            cmd,
            self.config.parallelism,
            query_type,
            self.local_id.clone(),
            target,
            value,
            peers,
            bootstrap,
        );
        self.queries.insert(id, query);
        id
    }

    /// Returns a reference to a query with the given ID, if it is in the pool.
    pub fn get(&self, id: &QueryId) -> Option<&QueryStream> {
        self.queries.get(id)
    }

    /// Returns a mutable reference to a query with the given ID, if it is in the pool.
    pub fn get_mut(&mut self, id: &QueryId) -> Option<&mut QueryStream> {
        self.queries.get_mut(id)
    }

    /// Polls the pool to advance the queries.
    pub fn poll(&mut self, now: Instant) -> QueryPoolState {
        let mut finished = None;
        let mut timeout = None;
        let mut waiting = None;

        debug!("queries len {} ", self.queries.len());
        for (&query_id, query) in self.queries.iter_mut() {
            query.stats.start = query.stats.start.or(Some(now));
            match query.poll(now) {
                Poll::Ready(Some(ev)) => {
                    waiting = Some((ev, query_id));
                    break;
                }
                Poll::Ready(None) => {
                    // query finished
                    finished = Some(query_id);
                    break;
                }
                Poll::Pending => {
                    let elapsed = now - query.stats.start.unwrap_or(now);
                    if elapsed >= self.config.timeout {
                        timeout = Some(query_id);
                        break;
                    }
                }
            }
        }

        if let Some((event, query_id)) = waiting {
            let query = self.queries.get_mut(&query_id).expect("s.a.");
            return QueryPoolState::Waiting(Some((query, event)));
        }

        if let Some(query_id) = finished {
            let mut query = self.queries.remove(&query_id).expect("s.a.");
            query.stats.end = Some(now);
            return QueryPoolState::Finished(query);
        }

        if let Some(query_id) = timeout {
            let mut query = self.queries.remove(&query_id).expect("s.a.");
            query.stats.end = Some(now);
            return QueryPoolState::Timeout(query);
        }

        if self.queries.is_empty() {
            return QueryPoolState::Idle;
        } else {
            return QueryPoolState::Waiting(None);
        }
    }
}

/// The observable states emitted by [`QueryPool::poll`].
pub enum QueryPoolState<'a> {
    /// The pool is idle, i.e. there are no queries to process.
    Idle,
    /// At least one query is waiting for results. `Some(request)` indicates
    /// that a new request is now being waited on.
    Waiting(Option<(&'a mut QueryStream, QueryEvent)>),
    /// A query has finished.
    Finished(QueryStream),
    /// A query has timed out.
    Timeout(QueryStream),
}

#[derive(Debug)]
pub struct QueryStream {
    /// identifier for this stream
    id: QueryId,
    /// The permitted parallelism, i.e. number of pending results.
    parallelism: NonZeroUsize,
    /// The peer iterator that drives the query state.
    peer_iter: QueryPeerIter,
    /// The rpc command of this stream
    cmd: Command,
    /// Stats about this query
    stats: QueryStats,
    /// Whether this stream should produce rpc messages of type [`Type::Query`] or [`Type::Update`]
    ty: QueryType,
    /// The value to include in each message
    value: Option<Vec<u8>>,
    /// The inner query state.
    pub inner: QueryTable,
}

impl QueryStream {
    pub fn bootstrap<T, I, S>(
        id: QueryId,
        cmd: T,
        parallelism: NonZeroUsize,
        ty: QueryType,
        local_id: Key<Vec<u8>>,
        target: Key<Vec<u8>>,
        value: Option<Vec<u8>>,
        peers: I,
        bootstrap: S,
    ) -> Self
    where
        T: Into<Command>,
        I: IntoIterator<Item = Key<PeerId>>,
        S: IntoIterator<Item = Peer>,
    {
        Self {
            id,
            parallelism,
            peer_iter: QueryPeerIter::Bootstrap(FixedPeersIter::new(bootstrap, parallelism)),
            cmd: cmd.into(),
            stats: QueryStats::empty(),
            value,
            ty,
            inner: QueryTable::new(local_id, target, peers),
        }
    }

    pub fn command(&self) -> &Command {
        &self.cmd
    }

    pub fn target(&self) -> &Key<Vec<u8>> {
        self.inner.target()
    }
    pub fn value(&self) -> Option<&Vec<u8>> {
        self.value.as_ref()
    }

    pub fn id(&self) -> QueryId {
        self.id
    }

    pub(crate) fn on_timeout(&mut self, peer: Peer) {
        self.stats.failure += 1;
        for (p, state) in self.inner.peers_mut() {
            if p.preimage().addr == peer.addr {
                *state = PeerState::Failed
            }
            break;
        }
        self.peer_iter.on_failure(&peer);
    }

    /// Received a response to a requested driven by this query.
    pub(crate) fn inject_response(&mut self, mut resp: Message, peer: Peer) -> Option<Response> {
        // check for errors
        let remote = resp.key(&peer)?;

        if resp.is_error() {
            self.stats.failure += 1;
            if let Some(state) = self.inner.peers_mut().get_mut(&remote) {
                *state = PeerState::Failed;
            }
            self.peer_iter.on_failure(&peer);
            // TODO return error?
            return None;
        }

        self.peer_iter.on_success(&peer);

        if let QueryPeerIter::MovingCloser(_) = self.peer_iter {
            for node in resp.decode_closer_nodes() {
                self.inner.add_unverified(node);
            }
            if !self.ty.is_query() {
                let to = resp.decode_to_peer();
                if let Some(token) = resp.roundtrip_token {
                    self.inner.add_verified(remote, token, to);
                }
                return None;
            }
        }

        if let Some(token) = resp.roundtrip_token.take() {
            self.inner
                .add_verified(remote.clone(), token, resp.decode_to_peer());
        }

        Some(Response {
            query: self.id,
            ty: self.ty,
            cmd: self.cmd.clone(),
            to: resp.decode_to_peer(),
            peer: PeerId::new(peer.addr, resp.id.take().expect("s.a")),
            value: resp.value,
        })
    }

    fn next_bootstrap(&mut self, state: PeersIterState) -> Poll<Option<QueryEvent>> {
        match state {
            PeersIterState::Waiting(peer) => {
                if let Some(peer) = peer {
                    Poll::Ready(Some(self.send(peer, false)))
                } else {
                    Poll::Pending
                }
            }
            PeersIterState::WaitingAtCapacity => Poll::Pending,
            PeersIterState::Finished => {
                self.peer_iter =
                    QueryPeerIter::MovingCloser(self.inner.unverified_peers_iter(self.parallelism));
                self.poll_iter()
            }
        }
    }

    fn next_move_closer(&mut self, state: PeersIterState) -> Poll<Option<QueryEvent>> {
        match state {
            PeersIterState::Waiting(peer) => {
                if let Some(peer) = peer {
                    Poll::Ready(Some(self.send(peer, false)))
                } else {
                    Poll::Pending
                }
            }
            PeersIterState::WaitingAtCapacity => Poll::Pending,
            PeersIterState::Finished => {
                if self.ty.is_update() {
                    self.inner.set_all_not_contacted();
                    self.peer_iter =
                        QueryPeerIter::Updating(self.inner.closest_peers_iter(self.parallelism));
                    self.poll_iter()
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }

    fn next_update(&mut self, state: PeersIterState) -> Poll<Option<QueryEvent>> {
        match state {
            PeersIterState::Waiting(peer) => {
                if let Some(peer) = peer {
                    Poll::Ready(Some(self.send(peer, true)))
                } else {
                    Poll::Pending
                }
            }
            PeersIterState::WaitingAtCapacity => Poll::Pending,
            PeersIterState::Finished => Poll::Ready(None),
        }
    }

    fn send(&self, peer: Peer, update: bool) -> QueryEvent {
        if update {
            if let Some(token) = self.inner.get_token(&peer) {
                QueryEvent::Update {
                    command: self.cmd.clone(),
                    token: Some(token.clone()),
                    target: self.target().preimage().clone(),
                    peer,
                    value: self.value.clone(),
                }
            } else {
                QueryEvent::MissingRoundtripToken { peer }
            }
        } else if self.ty.is_query() {
            QueryEvent::Query {
                command: self.cmd.clone(),
                target: self.target().preimage().clone(),
                value: self.value.clone(),
                peer,
            }
        } else {
            QueryEvent::Query {
                command: Command::FindNode,
                target: self.target().preimage().clone(),
                value: None,
                peer,
            }
        }
    }

    fn poll_iter(&mut self) -> Poll<Option<QueryEvent>> {
        match &mut self.peer_iter {
            QueryPeerIter::Bootstrap(iter) => {
                let state = iter.next();
                self.next_bootstrap(state)
            }
            QueryPeerIter::MovingCloser(iter) => {
                let state = iter.next();
                self.next_move_closer(state)
            }
            QueryPeerIter::Updating(iter) => {
                let state = iter.next();
                self.next_update(state)
            }
        }
    }

    fn poll(&mut self, now: Instant) -> Poll<Option<QueryEvent>> {
        self.poll_iter()
    }

    /// Consumes the query, producing the final `QueryResult`.
    pub fn into_result(self) -> QueryResult<QueryId, impl Iterator<Item = (PeerId, PeerState)>> {
        QueryResult {
            peers: self.inner.into_result(),
            inner: self.id,
            stats: self.stats,
            cmd: self.cmd,
        }
    }
}

/// The peer selection strategies that can be used by queries.
#[derive(Debug)]
enum QueryPeerIter {
    Bootstrap(FixedPeersIter),
    MovingCloser(FixedPeersIter),
    Updating(FixedPeersIter),
}

impl QueryPeerIter {
    fn on_success(&mut self, peer: &Peer) -> bool {
        match self {
            QueryPeerIter::Bootstrap(iter) => iter.on_success(peer),
            QueryPeerIter::MovingCloser(iter) => iter.on_success(peer),
            QueryPeerIter::Updating(iter) => iter.on_success(peer),
        }
    }

    fn on_failure(&mut self, peer: &Peer) -> bool {
        match self {
            QueryPeerIter::Bootstrap(iter) => iter.on_failure(peer),
            QueryPeerIter::MovingCloser(iter) => iter.on_failure(peer),
            QueryPeerIter::Updating(iter) => iter.on_failure(peer),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Query,
    Update,
    QueryUpdate,
}

impl QueryType {
    pub fn is_query(&self) -> bool {
        match self {
            QueryType::Query | QueryType::QueryUpdate => true,
            _ => false,
        }
    }

    pub fn is_update(&self) -> bool {
        match self {
            QueryType::Update | QueryType::QueryUpdate => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum QueryEvent {
    Query {
        peer: Peer,
        command: Command,
        target: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    RemoveNode {
        id: Vec<u8>,
    },
    MissingRoundtripToken {
        peer: Peer,
    },
    Update {
        peer: Peer,
        command: Command,
        target: Vec<u8>,
        value: Option<Vec<u8>>,
        token: Option<Vec<u8>>,
    },
}

/// Represents an incoming query with a custom command.
#[derive(Debug, Clone)]
pub struct CommandQuery {
    /// The Id of the query
    pub rid: RequestId,
    /// Whether this a query/update request
    pub ty: Type,
    /// Command def
    pub command: String,
    /// the node who sent the query/update
    // TODO change to `node`?
    pub node: Peer,
    /// the query/update target (32 byte target)
    pub target: Vec<u8>,
    /// the query/update payload decoded with the inputEncoding
    pub value: Option<Vec<u8>>,
}

impl CommandQuery {
    pub fn into_err(self, err: impl Into<String>) {
        unimplemented!()
    }
}

/// The result of a `Query`.
pub struct QueryResult<TInner, TPeers> {
    /// The opaque inner query state.
    pub inner: TInner,
    /// The successfully contacted peers.
    pub peers: TPeers,
    /// The collected query statistics.
    pub stats: QueryStats,
    /// The Command of the query.
    pub cmd: Command,
}

/// Unique identifier for an active query.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(usize);

/// Execution statistics of a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStats {
    requests: u32,
    success: u32,
    failure: u32,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl QueryStats {
    pub fn empty() -> Self {
        QueryStats {
            requests: 0,
            success: 0,
            failure: 0,
            start: None,
            end: None,
        }
    }

    /// Gets the total number of requests initiated by the query.
    pub fn num_requests(&self) -> u32 {
        self.requests
    }

    /// Gets the number of successful requests.
    pub fn num_successes(&self) -> u32 {
        self.success
    }

    /// Gets the number of failed requests.
    pub fn num_failures(&self) -> u32 {
        self.failure
    }

    /// Gets the number of pending requests.
    ///
    /// > **Note**: A query can finish while still having pending
    /// > requests, if the termination conditions are already met.
    pub fn num_pending(&self) -> u32 {
        self.requests - (self.success + self.failure)
    }

    /// Gets the duration of the query.
    ///
    /// If the query has not yet finished, the duration is measured from the
    /// start of the query to the current instant.
    ///
    /// If the query did not yet start (i.e. yield the first peer to contact),
    /// `None` is returned.
    pub fn duration(&self) -> Option<Duration> {
        if let Some(s) = self.start {
            if let Some(e) = self.end {
                Some(e - s)
            } else {
                Some(Instant::now() - s)
            }
        } else {
            None
        }
    }

    /// Merges these stats with the given stats of another query,
    /// e.g. to accumulate statistics from a multi-phase query.
    ///
    /// Counters are merged cumulatively while the instants for
    /// start and end of the queries are taken as the minimum and
    /// maximum, respectively.
    pub fn merge(self, other: QueryStats) -> Self {
        QueryStats {
            requests: self.requests + other.requests,
            success: self.success + other.success,
            failure: self.failure + other.failure,
            start: match (self.start, other.start) {
                (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
                (a, b) => a.or(b),
            },
            end: std::cmp::max(self.end, other.end),
        }
    }
}
