use std::net::SocketAddr;

use fnv::FnvHashMap;
use futures::task::Poll;
use libp2p_kad;
use wasm_timer::Instant;

use crate::kbucket::{Key, KeyBytes, ALPHA_VALUE};
use crate::rpc::message::{Command, Message, Type};
use crate::rpc::query::fixed::FixedPeersIter;
use crate::rpc::query::peers::PeersIterState;
use crate::rpc::query::table::QueryTable;
use crate::rpc::{Node, Peer, PeerId, RequestId};
use std::num::NonZeroUsize;
use std::time::Duration;

mod fixed;
mod peers;
mod table;

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to completion.
pub struct QueryPool {
    queries: FnvHashMap<QueryId, QueryStream>,
    next_id: usize,
}

impl QueryPool {
    /// Returns an iterator over the queries in the pool.
    pub fn iter(&self) -> impl Iterator<Item = &QueryStream> {
        self.queries.values()
    }

    /// Gets the current size of the pool, i.e. the number of running queries.
    pub fn size(&self) -> usize {
        self.queries.len()
    }

    fn next_query_id(&mut self) -> QueryId {
        let id = QueryId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Adds a query to the pool.
    pub fn add<T, I>(&mut self, cmd: T, peers: I) -> QueryId
    where
        T: Into<Command>,
        I: IntoIterator<Item = Key<PeerId>>,
    {
        unimplemented!()
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
        if self.queries.is_empty() {
            return QueryPoolState::Idle;
        } else {
            return QueryPoolState::Waiting(None);
        }
        unimplemented!()
    }
}

/// The observable states emitted by [`QueryPool::poll`].
pub enum QueryPoolState<'a> {
    /// The pool is idle, i.e. there are no queries to process.
    Idle,
    /// At least one query is waiting for results. `Some(request)` indicates
    /// that a new request is now being waited on.
    Waiting(Option<&'a mut QueryStream>),
    /// A query has finished.
    Finished(QueryStream),
    /// A query has timed out.
    Timeout(QueryStream),
}

pub struct QueryStream {
    id: QueryId,
    /// The permitted parallelism, i.e. number of pending results.
    parallelism: NonZeroUsize,
    /// The peer iterator that drives the query state.
    peer_iter: QueryPeerIter,
    cmd: Command,
    stats: QueryStats,
    ty: QueryType,
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
        local_id: KeyBytes,
        target: KeyBytes,
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

    pub fn target(&self) -> &KeyBytes {
        self.inner.target()
    }
    pub fn value(&self) -> Option<&Vec<u8>> {
        self.value.as_ref()
    }

    pub fn id(&self) -> QueryId {
        self.id
    }

    // TODO return data
    fn inject_response(&mut self) -> Option<()> {
        unimplemented!()
    }

    fn next_bootstrap(&mut self, state: PeersIterState) {
        match state {
            PeersIterState::Waiting(peer) => {
                if let Some(peer) = peer {
                } else {
                }
            }
            PeersIterState::WaitingAtCapacity => {}
            PeersIterState::Finished => {
                self.peer_iter =
                    QueryPeerIter::MovingCloser(self.inner.unverified_peers_iter(self.parallelism));
            }
        }
    }

    fn next_moving_closer(&mut self, state: PeersIterState) {
        match state {
            PeersIterState::Waiting(peer) => {}
            PeersIterState::WaitingAtCapacity => {}
            PeersIterState::Finished => {
                if self.ty.is_update() {
                    self.inner.set_all_not_contacted();
                    self.peer_iter =
                        QueryPeerIter::Updating(self.inner.closest_peers_iter(self.parallelism));
                } else {
                    self.peer_iter = QueryPeerIter::Finalized;
                }
            }
        }
    }

    fn next_update(&mut self, state: PeersIterState) {
        match state {
            PeersIterState::Waiting(peer) => {}
            PeersIterState::WaitingAtCapacity => {}
            PeersIterState::Finished => {}
        }
    }

    fn send(&self, peer: Peer, update: bool) {
        if update {
        } else if self.ty.is_query() {
        } else {
        }
    }

    // TODO tick call 5000?
    pub fn poll(&mut self) -> Option<QueryEvent> {
        let mut bootstrap = None;
        let mut moving = None;
        let mut updating = None;

        match &mut self.peer_iter {
            QueryPeerIter::Bootstrap(iter) => {
                bootstrap = Some(iter.next());
            }
            QueryPeerIter::MovingCloser(iter) => {
                moving = Some(iter.next());
            }
            QueryPeerIter::Updating(iter) => {
                updating = Some(iter.next());
            }
            QueryPeerIter::Finalized => {}
        }

        None
    }
}

/// The peer selection strategies that can be used by queries.
enum QueryPeerIter {
    Bootstrap(FixedPeersIter),
    MovingCloser(FixedPeersIter),
    Updating(FixedPeersIter),
    Finalized,
}

#[derive(Debug, Clone)]
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

pub enum QueryEvent {
    /// Request including retries failed completely
    Finished,
    Query {
        peer: Peer,
        command: Command,
        value: Option<Vec<u8>>,
    },
    RemoveNode {
        id: Vec<u8>,
    },
    Update {
        peer: Peer,
        command: Command,
        value: Option<Vec<u8>>,
        token: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone)]
pub struct Query {
    /// Whether this a query/update response
    pub ty: Type,
    /// Command def
    pub command: String,
    /// the node who sent the query/update
    // TODO change to `node`?
    pub node: Peer,
    /// the query/update target (32 byte target)
    pub target: Option<Vec<u8>>,
    /// the query/update payload decoded with the inputEncoding
    pub value: Option<Vec<u8>>,
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
