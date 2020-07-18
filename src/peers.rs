use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use smallvec::alloc::borrow::Borrow;

use crate::kbucket::{self, EntryView};
use crate::rpc::{IdBytes, Node, Peer, PeerId};

#[derive(Debug, Clone, Default)]
pub struct PeersCodec {
    id_length: usize,
}

impl PeersCodec {
    pub fn new(id_length: usize) -> Self {
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
                buf.extend_from_slice(&ip.octets()[..]);
                buf.extend_from_slice(&peer.addr.port().to_be_bytes()[..]);
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
    let port: [u8; 2] = peer[4..6].try_into().unwrap();
    let port = u16::from_be_bytes(port);
    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

pub fn decode_peer_ids(buf: impl AsRef<[u8]>) -> Vec<PeerId> {
    let buf = buf.as_ref();
    let mut peers = Vec::with_capacity(buf.len() / 38);

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
            id: IdBytes::try_from(&buf[0..32]).expect("s.a."),
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

impl PeersEncoding for Vec<EntryView<kbucket::Key<IdBytes>, Node>> {
    fn encode(&self) -> Vec<u8> {
        // TODO refactor
        let mut buf = Vec::with_capacity(self.len() * (32 + 6));

        for peer in self.iter() {
            let addr = &peer.node.value.addr;
            if let IpAddr::V4(ip) = addr.ip() {
                buf.extend_from_slice(peer.node.key.preimage().borrow());
                buf.extend_from_slice(&ip.octets()[..]);
                buf.extend_from_slice(&addr.port().to_be_bytes()[..]);
            }
        }
        buf
    }
}

impl PeersEncoding for Peer {
    fn encode(&self) -> Vec<u8> {
        self.addr.encode()
    }
}

impl PeersEncoding for SocketAddr {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6);
        // TODO what to do with IPV6?
        if let IpAddr::V4(ip) = self.ip() {
            buf.extend_from_slice(&ip.octets()[..]);
            buf.extend_from_slice(&self.port().to_be_bytes()[..]);
        }
        buf
    }
}

/// Decode local peers from a buffer.
pub fn decode_local_peers(local: &SocketAddrV4, buf: impl AsRef<[u8]>) -> Vec<SocketAddr> {
    let buf = buf.as_ref();
    if buf.len() & 3 == 0 {
        return vec![];
    }

    let octets = local.ip().octets();
    let mut peers = Vec::with_capacity(buf.len() / 4);

    for i in (0..buf.len()).step_by(4) {
        if let Ok(port) = buf[i + 2..i + 4].try_into() {
            let port = u16::from_be_bytes(port);
            peers.push(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(octets[0], octets[1], buf[i], buf[i + 1]),
                port,
            )))
        } else {
            return vec![];
        }
    }
    peers
}
