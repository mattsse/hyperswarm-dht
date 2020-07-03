use crate::kbucket::{Distance, Key, KeyBytes, K_VALUE};
use crate::rpc::message::Message;
use crate::rpc::query::fixed::FixedPeersIter;
use crate::rpc::{self, PeerId};
use std::collections::btree_map::{BTreeMap, Entry};
use std::net::SocketAddr;
use std::{iter::FromIterator, num::NonZeroUsize, time::Duration};
use wasm_timer::Instant;

#[derive(Debug)]
pub struct QueryTable {
    id: Key<Vec<u8>>,
    target: Key<Vec<u8>>,
    /// The closest peers to the target, ordered by increasing distance.
    // TODO change to simple Vec?
    closest_peers: BTreeMap<Distance, Peer>,
}

impl QueryTable {
    pub fn new<T>(id: Key<Vec<u8>>, target: Key<Vec<u8>>, known_closest_peers: T) -> Self
    where
        T: IntoIterator<Item = Key<PeerId>>,
    {
        // Initialise the closest peers to start the iterator with.
        let closest_peers = BTreeMap::from_iter(known_closest_peers.into_iter().map(|key| {
            let distance = key.distance(&target);
            let state = PeerState::NotContacted;
            (distance, Peer { key, state })
        }));

        Self {
            id,
            target,
            closest_peers,
        }
    }

    pub fn target(&self) -> &Key<Vec<u8>> {
        &self.target
    }

    pub(crate) fn get_peer(&self, peer: &rpc::Peer) -> Option<&Peer> {
        self.closest_peers
            .values()
            .filter(|p| p.key.preimage().addr == peer.addr)
            .next()
    }

    pub fn get_token(&self, peer: &rpc::Peer) -> Option<&Vec<u8>> {
        self.closest_peers
            .values()
            .filter(|p| p.key.preimage().addr == peer.addr)
            .map(|p| p.state.get_token())
            .next()
            .flatten()
    }

    pub fn unverified_peers_iter(&self, parallelism: NonZeroUsize) -> FixedPeersIter {
        FixedPeersIter::new(
            self.closest_peers
                .values()
                .filter(|p| p.state.is_not_contacted())
                .map(|p| rpc::Peer::from(p.key.preimage().addr)),
            parallelism,
        )
    }

    pub fn closest_peers_iter(&self, parallelism: NonZeroUsize) -> FixedPeersIter {
        FixedPeersIter::new(
            self.closest_peers
                .values()
                .take(K_VALUE.into())
                .map(|p| rpc::Peer::from(p.key.preimage().addr)),
            parallelism,
        )
    }

    pub fn add_unverified(&mut self, peer: PeerId) {
        let peer = Peer {
            key: Key::new(peer),
            state: PeerState::NotContacted,
        };
        let distance = self.target.distance(&peer.key);
        self.closest_peers.insert(distance, peer);
    }

    pub fn add_verified(&mut self, peer: PeerId, roundtrip_token: Vec<u8>) {
        let key = Key::new(peer);
        if key == self.id {
            return;
        }
        if let Some(prev) = self
            .closest_peers
            .values_mut()
            .filter(|p| p.key.as_ref() == key.as_ref())
            .next()
        {
            prev.state = PeerState::Succeeded { roundtrip_token };
        } else {
            let peer = Peer {
                key,
                state: PeerState::Succeeded { roundtrip_token },
            };
            let distance = self.target.distance(&peer.key);
            self.closest_peers.insert(distance, peer);
        }
    }

    /// Set the state of every `Peer` to `PeerState::NotContacted`
    pub fn set_all_not_contacted(&mut self) {
        for peer in self.closest_peers.values_mut() {
            peer.state = PeerState::NotContacted;
        }
    }
}

/// Representation of a peer in the context of a iterator.
#[derive(Debug, Clone)]
pub(crate) struct Peer {
    key: Key<PeerId>,
    state: PeerState,
}

impl Peer {
    pub(crate) fn state(&self) -> &PeerState {
        &self.state
    }
}

/// The state of a single `Peer`.
#[derive(Debug, Clone)]
pub(crate) enum PeerState {
    /// The peer has not yet been contacted.
    ///
    /// This is the starting state for every peer.
    NotContacted,

    /// The iterator is waiting for a result from the peer.
    Waiting(Instant),

    /// A result was not delivered for the peer within the configured timeout.
    ///
    /// The peer is not taken into account for the termination conditions
    /// of the iterator until and unless it responds.
    Unresponsive,

    /// Obtaining a result from the peer has failed.
    ///
    /// This is a final state, reached as a result of a call to `on_failure`.
    Failed,

    /// A successful result from the peer has been delivered.
    ///
    /// This is a final state, reached as a result of a call to `on_success`.
    Succeeded { roundtrip_token: Vec<u8> },
}

impl PeerState {
    fn is_verified(&self) -> bool {
        match self {
            PeerState::Succeeded { .. } => true,
            _ => false,
        }
    }

    fn is_not_contacted(&self) -> bool {
        match self {
            PeerState::NotContacted => true,
            _ => false,
        }
    }

    pub(crate) fn get_token(&self) -> Option<&Vec<u8>> {
        match self {
            PeerState::Succeeded { roundtrip_token } => Some(roundtrip_token),
            _ => None,
        }
    }
}
