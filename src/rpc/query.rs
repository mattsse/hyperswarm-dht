use crate::rpc::message::Type;
use crate::rpc::Peer;

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to completion.
pub struct QueryPool {}

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
