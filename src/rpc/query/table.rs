use crate::kbucket::{Distance, Key, KeyBytes, K_VALUE};
use crate::rpc::message::Message;
use crate::rpc::PeerId;
use std::collections::btree_map::{BTreeMap, Entry};
use std::net::SocketAddr;
use std::{iter::FromIterator, num::NonZeroUsize, time::Duration};
use wasm_timer::Instant;

pub struct QueryTable {
    id: KeyBytes,
    target: KeyBytes,
    /// The closest peers to the target, ordered by increasing distance.
    // TODO change to simple Vec?
    closest_peers: BTreeMap<Distance, Peer>,
}

impl QueryTable {
    pub fn new<T>(id: KeyBytes, target: KeyBytes, known_closest_peers: T) -> Self
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
        if key.as_ref() == &self.id {
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
    fn set_not_contacted_all(&mut self) {
        for peer in self.closest_peers.values_mut() {
            peer.state = PeerState::NotContacted;
        }
    }
}

#[derive(Debug, Clone)]
struct QueryPeer {
    id: KeyBytes,
    addr: SocketAddr,
    roundtrip_token: Option<Vec<u8>>,
    referrer: Option<SocketAddr>,
}

/// Representation of a peer in the context of a iterator.
#[derive(Debug, Clone)]
struct Peer {
    key: Key<PeerId>,
    state: PeerState,
}

/// The state of a single `Peer`.
#[derive(Debug, Clone)]
enum PeerState {
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
