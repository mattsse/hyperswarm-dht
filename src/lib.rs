#![allow(unused)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use futures::task::{Context, Poll};
use futures::Stream;

use crate::dht_proto::PeersInput;
use crate::kbucket::KBucketsTable;
use crate::peers::{PeersCodec, PeersEncoding};
use crate::rpc::query::{QueryCommand, QueryId};
use crate::rpc::{DhtConfig, PeerId, Response, RpcDht};
use ed25519_dalek::PublicKey;
use fnv::FnvHashMap;
use prost::Message;
use std::convert::{TryFrom, TryInto};

mod dht_proto {
    include!(concat!(env!("OUT_DIR"), "/dht_pb.rs"));
}

pub mod crypto;
pub mod kbucket;
pub mod peers;
pub mod rpc;
pub mod stores;

const EPH_AFTER: u64 = 1000 * 60 * 20;

const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "bootstrap1.hyperdht.org:49737",
    "bootstrap2.hyperdht.org:49737",
    "bootstrap3.hyperdht.org:49737",
];

const MUTABLE_STORE_CMD: &str = "mutable-store";
const IMMUTABLE_STORE_CMD: &str = "immutable-store";
const PEERS_CMD: &str = "peers";

pub struct HyperDht {
    queries: FnvHashMap<QueryId, QueryStreamType>,
    inner: RpcDht, // TODO map between queries and stores.
    adaptive: bool,
}

impl HyperDht {
    pub async fn with_config(mut config: DhtConfig) -> io::Result<Self> {
        config = config.register_commands(&[MUTABLE_STORE_CMD, IMMUTABLE_STORE_CMD, PEERS_CMD]);
        if config.bootstrap_nodes().is_empty() {
            config = config.add_bootstrap_nodes(&DEFAULT_BOOTSTRAP[..]);
        }

        Ok(Self {
            adaptive: config.adaptive,
            queries: Default::default(),
            inner: RpcDht::with_config(config).await?,
        })
    }

    /// Handle an incoming request for the registered commands
    fn on_command(&mut self, q: QueryCommand) {
        // TODO decode q.value and reply
        match q.command.as_str() {
            MUTABLE_STORE_CMD => {}
            IMMUTABLE_STORE_CMD => {}
            PEERS_CMD => {}
            s => {
                // additional registered command -> return
            }
        }
    }

    fn on_peers(&mut self) {
        unimplemented!()
    }

    /// Look for peers in the DHT on the given topic.
    pub fn lookup(&mut self, opts: impl Into<QueryOpts>) -> QueryId {
        let opts = opts.into();

        let peers = PeersInput {
            port: opts.port,
            local_address: opts.local_addr_encoded(),
            unannounce: None,
        };

        let mut buf = Vec::with_capacity(peers.encoded_len());

        // vec has sufficient capacity up to usize::MAX
        peers.encode(&mut buf).unwrap();

        let id = self
            .inner
            .query(PEERS_CMD, kbucket::Key::new(opts.topic.to_vec()), Some(buf));
        self.queries.insert(id, QueryStreamType::LookUp(vec![]));
        id
    }

    /// Announce a port to the dht.
    pub fn announce(&mut self, opts: impl Into<QueryOpts>) -> QueryId {
        let opts = opts.into();

        let peers = PeersInput {
            port: opts.port,
            local_address: opts.local_addr_encoded(),
            unannounce: None,
        };

        let mut buf = Vec::with_capacity(peers.encoded_len());

        // vec has sufficient capacity up to usize::MAX
        peers.encode(&mut buf).unwrap();

        let id = self.inner.query_and_update(
            PEERS_CMD,
            kbucket::Key::new(opts.topic.to_vec()),
            Some(buf),
        );
        self.queries.insert(id, QueryStreamType::Announce(vec![]));
        id
    }

    pub fn unannounce(&mut self, opts: impl Into<QueryOpts>) -> QueryId {
        let opts = opts.into();

        let peers = PeersInput {
            port: opts.port,
            local_address: opts.local_addr_encoded(),
            unannounce: Some(true),
        };

        let mut buf = Vec::with_capacity(peers.encoded_len());

        // vec has sufficient capacity up to usize::MAX
        peers.encode(&mut buf).unwrap();

        let id = self
            .inner
            .update(PEERS_CMD, kbucket::Key::new(opts.topic.to_vec()), Some(buf));
        self.queries.insert(id, QueryStreamType::UnAnnounce(vec![]));
        id
    }
}

impl Stream for HyperDht {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // delegate query response to on peers
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct QueryOpts {
    /// The topic to announce
    pub topic: [u8; 32],
    /// Explicitly set the port you want to announce. Per default the UDP socket port is announced.
    pub port: Option<u32>,
    /// Optionally announce a LAN address as well. Only people with the same public IP as you will get these when doing a lookup
    pub local_addr: Option<SocketAddr>,
}

impl QueryOpts {
    fn local_addr_encoded(&self) -> Option<Vec<u8>> {
        self.local_addr.as_ref().map(|addr| addr.encode())
    }
}

impl From<&PublicKey> for QueryOpts {
    fn from(key: &PublicKey) -> Self {
        Self {
            topic: key.to_bytes(),
            port: None,
            local_addr: None,
        }
    }
}

impl From<[u8; 32]> for QueryOpts {
    fn from(topic: [u8; 32]) -> Self {
        Self {
            topic,
            port: None,
            local_addr: None,
        }
    }
}

impl TryFrom<&[u8]> for QueryOpts {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            topic: value.try_into()?,
            port: None,
            local_addr: None,
        })
    }
}

// TODO add actual types
pub enum HyperDhtEvent {
    /// The result of [`HyperDht::announce`].
    AnnounceResult,
    /// The result of [`HyperDht::unannounce`].
    UnAnnounceResult,
    /// The result of [`HyperDht::lookup`].
    LookupResult,
}

pub struct LookupOk {
    /// The DHT node that is returning this data
    node: PeerId,
    to: Option<SocketAddr>,
    /// List of peers
    peers: Vec<SocketAddr>,
    /// List of LAN peers
    local_peers: Vec<SocketAddr>,
}

/// Type to keep track of the responses for queries in progress.
enum QueryStreamType {
    LookUp(Vec<Response>),
    Announce(Vec<Response>),
    UnAnnounce(Vec<Response>),
}

impl QueryStreamType {
    fn inner_mut(&mut self, resp: Response) -> &mut Vec<Response> {
        match self {
            QueryStreamType::LookUp(r)
            | QueryStreamType::Announce(r)
            | QueryStreamType::UnAnnounce(r) => r,
        }
    }

    fn inner(&self, resp: Response) -> &Vec<Response> {
        match self {
            QueryStreamType::LookUp(r)
            | QueryStreamType::Announce(r)
            | QueryStreamType::UnAnnounce(r) => r,
        }
    }
}
