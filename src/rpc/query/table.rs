use std::net::SocketAddr;
use std::{iter::FromIterator, num::NonZeroUsize};

use fnv::FnvHashMap;

use crate::kbucket::{Distance, Key, KeyBytes, K_VALUE};
use crate::rpc::query::fixed::FixedPeersIter;
use crate::rpc::{self, IdBytes, PeerId};

#[derive(Debug)]
pub struct QueryTable {
    id: Key<IdBytes>,
    target: Key<IdBytes>,
    /// The closest peers to the target.
    peers: FnvHashMap<Key<PeerId>, PeerState>,
}

impl QueryTable {
    pub fn new<T>(id: Key<IdBytes>, target: Key<IdBytes>, known_closest_peers: T) -> Self
    where
        T: IntoIterator<Item = Key<PeerId>>,
    {
        // Initialise the closest peers to start the iterator with.
        let peers = FnvHashMap::from_iter(
            known_closest_peers
                .into_iter()
                .map(|key| (key, PeerState::NotContacted)),
        );

        Self { id, target, peers }
    }

    pub(crate) fn peers(&self) -> &FnvHashMap<Key<PeerId>, PeerState> {
        &self.peers
    }

    pub(crate) fn peers_mut(&mut self) -> &mut FnvHashMap<Key<PeerId>, PeerState> {
        &mut self.peers
    }

    pub fn target(&self) -> &Key<IdBytes> {
        &self.target
    }

    pub(crate) fn get_peer(&self, peer: &rpc::Peer) -> Option<rpc::Peer> {
        self.peers
            .keys()
            .filter(|p| p.preimage().addr == peer.addr)
            .map(|p| rpc::Peer::from(p.preimage().addr))
            .next()
    }

    pub fn get_token(&self, peer: &rpc::Peer) -> Option<&Vec<u8>> {
        self.peers
            .iter()
            .filter(|(p, _)| p.preimage().addr == peer.addr)
            .map(|(_, s)| s.get_token())
            .next()
            .flatten()
    }

    pub fn unverified_peers_iter(&self, parallelism: NonZeroUsize) -> FixedPeersIter {
        FixedPeersIter::new(
            self.peers
                .iter()
                .filter(|(_, s)| s.is_not_contacted())
                .map(|(p, _)| rpc::Peer::from(p.preimage().addr)),
            parallelism,
        )
    }

    pub fn closest_peers_iter(&self, parallelism: NonZeroUsize) -> FixedPeersIter {
        let mut peers = self
            .peers
            .iter()
            .filter(|(_, s)| s.is_not_contacted())
            .map(|(p, _)| p)
            .collect::<Vec<_>>();

        peers.sort_by(|a, b| self.target.distance(a).cmp(&self.target.distance(b)));

        FixedPeersIter::new(
            peers
                .into_iter()
                .take(usize::from(K_VALUE))
                .map(|p| rpc::Peer::from(p.preimage().addr)),
            parallelism,
        )
    }

    pub(crate) fn add_unverified(&mut self, peer: PeerId) {
        self.peers.insert(Key::new(peer), PeerState::NotContacted);
    }

    pub(crate) fn add_verified(
        &mut self,
        key: Key<PeerId>,
        roundtrip_token: Vec<u8>,
        to: Option<SocketAddr>,
    ) {
        if key == self.id {
            return;
        }
        if let Some(prev) = self.peers.get_mut(&key) {
            *prev = PeerState::Succeeded {
                roundtrip_token,
                to,
            };
        } else {
            self.peers.insert(
                key,
                PeerState::Succeeded {
                    roundtrip_token,
                    to,
                },
            );
        }
    }

    /// Set the state of every `Peer` to `PeerState::NotContacted`
    pub fn set_all_not_contacted(&mut self) {
        for state in self.peers.values_mut() {
            *state = PeerState::NotContacted;
        }
    }

    pub(crate) fn into_result(self) -> impl Iterator<Item = (PeerId, PeerState)> {
        self.peers.into_iter().map(|(k, v)| (k.into_preimage(), v))
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
pub enum PeerState {
    /// The peer has not yet been contacted.
    ///
    /// This is the starting state for every peer.
    NotContacted,

    /// Obtaining a result from the peer has failed.
    ///
    /// This is a final state, reached as a result of a call to `on_failure`.
    Failed,

    /// A successful result from the peer has been delivered.
    ///
    /// This is a final state, reached as a result of a call to `on_success`.
    Succeeded {
        roundtrip_token: Vec<u8>,
        to: Option<SocketAddr>,
    },
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
            PeerState::Succeeded {
                roundtrip_token, ..
            } => Some(roundtrip_token),
            _ => None,
        }
    }
}
