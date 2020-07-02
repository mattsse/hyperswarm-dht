use std::{borrow::Cow, collections::hash_map::Entry, num::NonZeroUsize, vec};

use fnv::FnvHashMap;

use crate::rpc::query::peers::PeersIterState;
use crate::rpc::Peer;

/// A peer iterator for a fixed set of peers.
pub struct BootstrapPeersIter {
    /// The permitted parallelism, i.e. number of pending results.
    parallelism: NonZeroUsize,

    /// The state of peers emitted by the iterator.
    peers: FnvHashMap<Peer, PeerState>,

    /// The backlog of peers that can still be emitted.
    iter: vec::IntoIter<Peer>,

    /// The internal state of the iterator.
    state: State,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Waiting { num_waiting: usize },
    Finished,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum PeerState {
    /// The iterator is waiting for a result to be reported back for the peer.
    Waiting,

    /// The iterator has been informed that the attempt to contact the peer failed.
    Failed,

    /// The iterator has been informed of a successful result from the peer.
    Succeeded,
}

impl BootstrapPeersIter {
    pub fn new<I>(peers: I, parallelism: NonZeroUsize) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        let peers = peers.into_iter().collect::<Vec<_>>();

        Self {
            parallelism,
            iter: peers.into_iter(),
            peers: Default::default(),
            state: State::Waiting { num_waiting: 0 },
        }
    }

    pub fn on_success(&mut self, peer: &Peer) -> bool {
        if let State::Waiting { num_waiting } = &mut self.state {
            *num_waiting -= 1;
            return true;
        }
        false
    }

    pub fn finish(&mut self) {
        if let State::Waiting { .. } = self.state {
            self.state = State::Finished
        }
    }

    /// Checks whether the iterator has finished.
    pub fn is_finished(&self) -> bool {
        self.state == State::Finished
    }

    pub fn next(&mut self) -> PeersIterState {
        match &mut self.state {
            State::Finished => return PeersIterState::Finished,
            State::Waiting { num_waiting } => {
                if *num_waiting >= self.parallelism.get() {
                    return PeersIterState::WaitingAtCapacity;
                }
                loop {
                    match self.iter.next() {
                        None => {
                            if *num_waiting == 0 {
                                self.state = State::Finished;
                                return PeersIterState::Finished;
                            } else {
                                return PeersIterState::Waiting(None);
                            }
                        }
                        Some(p) => match self.peers.entry(p.clone()) {
                            Entry::Occupied(_) => {} // skip duplicates
                            Entry::Vacant(e) => {
                                *num_waiting += 1;
                                e.insert(PeerState::Waiting);
                                return PeersIterState::Waiting(Some(Cow::Owned(p)));
                            }
                        },
                    }
                }
            }
        }
    }
}
