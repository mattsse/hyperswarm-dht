use crate::kbucket::{self, EntryView, KeyBytes};
use crate::rpc::Peer;
use bytes::{Buf, BufMut};
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use std::net::IpAddr;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};

#[derive(Debug, Clone, Default)]
pub struct PeersCodec {
    id_length: usize,
}

impl PeersCodec {
    pub(crate) fn new(id_length: usize) -> Self {
        Self { id_length }
    }
}

pub trait PeersEncoding {
    fn encode(&self) -> Vec<u8>;
}

impl PeersEncoding for &[Peer] {
    fn encode(&self) -> Vec<u8> {
        unimplemented!()
    }
}

impl PeersEncoding for Vec<EntryView<kbucket::Key<GenericArray<u8, U32>>, SocketAddr>> {
    fn encode(&self) -> Vec<u8> {
        // TODO refactor
        let mut buf = Vec::with_capacity(self.len() * (32 + 6));

        for peer in self.iter() {
            if let IpAddr::V4(ip) = peer.node.value.ip() {
                buf.copy_from_slice(&peer.node.key.preimage());
                buf.copy_from_slice(&ip.octets()[..]);
                buf.copy_from_slice(&peer.node.value.port().to_be_bytes()[..]);
            }
        }
        buf
    }
}

impl PeersEncoding for Peer {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6);
        // TODO what to do with IPV6?
        if let IpAddr::V4(ip) = self.addr.ip() {
            buf.copy_from_slice(&ip.octets()[..]);
            buf.copy_from_slice(&self.addr.port().to_be_bytes()[..]);
        }
        buf
    }
}
