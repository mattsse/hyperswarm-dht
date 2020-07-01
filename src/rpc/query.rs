use crate::kbucket::KeyBytes;
use crate::rpc::message::{Command, Message, Type};
use crate::rpc::{Node, Peer, RequestId};
use fnv::FnvHashMap;
use futures::task::Poll;
use std::net::SocketAddr;
use wasm_timer::Instant;

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to completion.
pub struct QueryPool {
    // TODO change to queryid?
    queries: FnvHashMap<QueryId, QueryStream>,
    next_id: usize,
}

impl QueryPool {
    pub fn inject_response(&mut self, req: Message, response: Message, peer: Peer) {
        // equals the callback executed in js io::_finish
    }

    fn next_query_id(&mut self) -> QueryId {
        let id = QueryId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    pub fn poll(&mut self) -> Poll<Option<QueryEvent>> {
        unimplemented!()
    }
}

/// The observable states emitted by [`QueryPool::poll`].
pub enum QueryPoolState<'a> {
    /// The pool is idle, i.e. there are no queries to process.
    Idle,
    /// At least one query is waiting for results. `Some(request)` indicates
    /// that a new request is now being waited on.
    Waiting(Option<(&'a mut QueryStream, Peer)>),
    /// A query has finished.
    Finished(QueryStream),
    /// A query has timed out.
    Timeout(QueryStream),
}

pub struct QueryStream {
    id: QueryId,
    cmd: Command,
    table: QueryTable,
    status: QueryStatus,
    stats: QueryStats,
}

impl QueryStream {
    pub fn bootstrap(&mut self) {}
}

/// Execution statistics of a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStats {
    requests: u32,
    success: u32,
    failure: u32,
    start: Option<Instant>,
    end: Option<Instant>,
}

pub enum QueryEvent {
    /// Request including retries failed completely
    RemoveNode { id: Vec<u8> },
    Response {
        ty: Type,
        to: Option<SocketAddr>,
        id: Option<Vec<u8>>,
        peer: Peer,
        value: Option<Vec<u8>>,
        cmd: Command,
    },
}

pub struct QueryTable {
    k: u64,
    id: KeyBytes,
    target: KeyBytes,
    closest: Vec<Node>,
    unverified: Vec<Node>,
}

impl QueryTable {
    pub fn new(id: KeyBytes, target: KeyBytes) -> Self {
        Self {
            k: 20,
            id,
            target,
            closest: vec![],
            unverified: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub enum QueryStatus {
    Bootstrapping,
    MovingCloser,
    Updating,
    Finalized,
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
