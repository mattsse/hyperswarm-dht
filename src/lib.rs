#![allow(unused)]

use crate::kbucket::KBucketsTable;
use futures::task::{Context, Poll};
use futures::Stream;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

mod dht_proto {
    include!(concat!(env!("OUT_DIR"), "/dht_pb.rs"));
}

pub mod kbucket;
pub mod peers;
pub mod rpc;
pub mod sign;
pub mod stores;

const EPH_AFTER: u64 = 1000 * 60 * 20;

const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "bootstrap1.hyperdht.org:49737",
    "bootstrap2.hyperdht.org:49737",
    "bootstrap3.hyperdht.org:49737",
];

pub struct HyperDHT {
    // kbuckets: KBucketsTable<kbucket::Key<PeerId>, Addresses>,
}

impl Stream for HyperDHT {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        unimplemented!()
    }
}

impl HyperDHT {
    async fn init(&mut self) {
        // create udpsocket
        // create bucket with local id

        unimplemented!()
    }

    pub async fn announce(&mut self) {
        unimplemented!()
    }

    pub async fn unannounce(&mut self) {
        unimplemented!()
    }

    pub async fn listen(&mut self) {
        unimplemented!()
    }
}

pub struct HyperDHTBuilder {
    /// Optionally overwrite the default bootstrap servers
    bootstrap: Option<Vec<String>>,
    /// If you are a shortlived client or don't want to host
    /// data join as an ephemeral node. (defaults to false)
    ephemeral: bool,
    /// if set to true, the adaptive option will cause the node to become non-ephemeral after the node has shown to be long-lived (defaults to false)
    adaptive: bool,
    /// Time until a peer is dropped
    max_age: Duration,
}

pub struct Announce {
    /// Explicitly set the port you want to announce. Per default you UDP socket port is announced.
    port: Option<u16>,
    local_address: Option<SocketAddr>,
    /// Optionally include the announced data length of each peer in the response
    include_length: Option<bool>,
    /// Optionally announce your local data length as well.
    len: Option<u64>,
}
