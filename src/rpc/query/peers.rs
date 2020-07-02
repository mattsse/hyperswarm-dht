use std::borrow::Cow;

use crate::rpc::Peer;

/// The state of a peer iterator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeersIterState<'a> {
    /// The iterator is waiting for results.
    ///
    /// `Some(peer)` indicates that the iterator is now waiting for a result
    /// from `peer`, in addition to any other peers for which it is already
    /// waiting for results.
    ///
    /// `None` indicates that the iterator is waiting for results and there is no
    /// new peer to contact, despite the iterator not being at capacity w.r.t.
    /// the permitted parallelism.
    Waiting(Option<Cow<'a, Peer>>),

    /// The iterator is waiting for results and is at capacity w.r.t. the
    /// permitted parallelism.
    WaitingAtCapacity,

    /// The iterator finished.
    Finished,
}
