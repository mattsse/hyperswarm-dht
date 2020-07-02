use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};

use bytes::{Buf, BufMut};

use crate::kbucket::{self, EntryView, KeyBytes};
use crate::rpc::{Node, Peer, PeerId};

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
        let mut buf = Vec::with_capacity(self.len() * 6);
        for peer in self.iter() {
            // TODO what to do with IPV6?
            if let IpAddr::V4(ip) = peer.addr.ip() {
                buf.copy_from_slice(&ip.octets()[..]);
                buf.copy_from_slice(&peer.addr.port().to_be_bytes()[..]);
            }
        }
        buf
    }
}

fn decode_addr(peer: &[u8]) -> Option<SocketAddr> {
    if peer.len() != 6 {
        return None;
    }

    let octects: [u8; 4] = peer[0..4].try_into().unwrap();
    let ip = Ipv4Addr::from(octects);
    let port = u16::from_be_bytes(peer[5..6].try_into().unwrap());
    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

pub fn decode_peer_id(buf: impl AsRef<[u8]>) -> Vec<PeerId> {
    let buf = buf.as_ref();
    let mut peers = Vec::with_capacity(buf.len() / 48);

    for chunk in buf.chunks(38) {
        if let Ok(peer) = chunk.try_into() {
            peers.push(peer);
        }
    }

    peers
}

impl TryFrom<&[u8]> for PeerId {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let buf = value.as_ref();
        if buf.len() != 38 {
            return Err(());
        }

        Ok(PeerId {
            id: buf[0..32].to_vec(),
            addr: decode_addr(&buf[32..]).expect("s.a."),
        })
    }
}

pub fn decode_peers(buf: impl AsRef<[u8]>) -> Vec<SocketAddr> {
    let buf = buf.as_ref();
    let mut peers = Vec::with_capacity(buf.len() / 6);

    for peer in buf.chunks(6) {
        if let Some(addr) = decode_addr(peer) {
            peers.push(addr);
        }
    }
    peers
}

impl PeersEncoding for Vec<EntryView<kbucket::Key<Vec<u8>>, Node>> {
    fn encode(&self) -> Vec<u8> {
        // TODO refactor
        let mut buf = Vec::with_capacity(self.len() * (32 + 6));

        for peer in self.iter() {
            let addr = &peer.node.value.addr;
            if let IpAddr::V4(ip) = addr.ip() {
                buf.copy_from_slice(&peer.node.key.preimage());
                buf.copy_from_slice(&ip.octets()[..]);
                buf.copy_from_slice(&addr.port().to_be_bytes()[..]);
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
