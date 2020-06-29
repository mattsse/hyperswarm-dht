use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use blake2_rfc::blake2b::{blake2b, Blake2b, Blake2bResult};
use bytes::Bytes;
use fnv::FnvHashMap;
use futures::{
    pin_mut,
    task::{Context, Poll},
    Sink,
};
use prost::Message as ProtoMessage;
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use tokio::{net::UdpSocket, stream::Stream};
use tokio_util::{codec::Encoder, udp::UdpFramed};
use wasm_timer::Instant;

use crate::{
    kbucket::KeyBytes,
    peers::PeersEncoding,
    rpc::message::{Command, Message, Type},
    rpc::protocol::DhtRpcCodec,
    rpc::{Peer, RequestId, RoundTripPeer},
};

pub const VERSION: u64 = 1;

const ROTATE_INTERVAL: u64 = 300_000;

pub struct Request {
    /// The message send
    message: Message,
    /// The remote peer
    peer: Peer,
    /// Timestamp when the request was sent
    timestamp: Instant,
}

// TODO merge this with the DHT struct
pub struct Io {
    id: GenericArray<u8, U32>,
    socket: UdpFramed<DhtRpcCodec>,
    pending_send: VecDeque<(Message, Peer)>,
    pending_flush: Option<(Message, Peer)>,
    // TODO id as key
    pending_recv: FnvHashMap<RequestId, Request>,
    secrets: ([u8; 32], [u8; 32]),

    /// The TTL of regular (value-)records.
    record_ttl: Option<Duration>,

    /// The TTL of provider records.
    provider_record_ttl: Option<Duration>,

    next_req_id: RequestId,

    rotation: Duration,
    last_rotation: Instant,
}

impl Io {
    /// Generate the next request id
    fn next_req_id(&mut self) -> RequestId {
        let rid = self.next_req_id;
        self.next_req_id = RequestId(self.next_req_id.0.checked_add(1).unwrap_or_default());
        rid
    }

    pub fn address(&self) -> &SocketAddr {
        unimplemented!()
    }

    /// Generate a blake2 hash based on the peer's ip and the provided secret
    fn token(&self, peer: &Peer, secret: &[u8]) -> Blake2bResult {
        let mut context = Blake2b::new(32);
        context.update(secret);
        context.update(peer.addr.ip().to_string().as_bytes());
        context.finalize()
    }

    pub fn holepunch(&mut self, peer: SocketAddr, referrer: SocketAddr) -> anyhow::Result<()> {
        unimplemented!()
    }

    /// Start sending a new message if any is pending
    fn send_next_pending(&mut self) -> io::Result<()> {
        if let Some((msg, peer)) = self.pending_send.pop_front() {
            let mut buf = Vec::with_capacity(msg.encoded_len());
            msg.encode(&mut buf)?;
            let socket = &mut self.socket;
            pin_mut!(socket);
            Sink::start_send(socket, (buf, peer.addr.clone()))?;

            self.pending_flush = Some((msg, peer));
        }
        Ok(())
    }

    /// Send the message to the peer
    ///
    /// If we're currently busy with sending another message, the message gets queued in
    pub fn send_to(&mut self, msg: Message, peer: Peer) -> anyhow::Result<()> {
        if self.pending_flush.is_none() {
            let mut buffer = Vec::with_capacity(msg.encoded_len());
            msg.encode(&mut buffer)?;
            let socket = &mut self.socket;
            pin_mut!(socket);
            Sink::start_send(socket, (buffer, peer.addr.clone()))?;
            self.pending_flush = Some((msg, peer));
        } else {
            self.pending_send.push_back((msg, peer));
        }
        Ok(())
    }

    /// Send a new Query message
    pub fn query(
        &mut self,
        cmd: Command,
        target: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        peer: Peer,
    ) -> anyhow::Result<()> {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Query.id(),
            rid: 0,
            to: Some(peer.encode()),
            id: Some(self.id.as_slice().to_vec()),
            target,
            closer_nodes: None,
            roundtrip_token: None,
            command: Some(cmd.to_string()),
            error: None,
            value,
        };
        Ok(self.send_to(msg, peer)?)
    }

    pub fn request(&mut self) {
        unimplemented!()
    }

    pub fn error(
        &mut self,
        request: Message,
        error: Option<String>,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<u8>>,
        peer: Peer,
    ) -> anyhow::Result<()> {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Response.id(),
            rid: request.rid,
            to: Some(peer.encode()),
            id: Some(self.id.as_slice().to_vec()),
            target: None,
            closer_nodes,
            roundtrip_token: None,
            command: None,
            error,
            value,
        };
        Ok(self.send_to(msg, peer)?)
    }

    pub fn response(
        &mut self,
        request: Message,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<u8>>,
        peer: Peer,
    ) -> anyhow::Result<()> {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Response.id(),
            rid: request.rid,
            to: Some(peer.encode()),
            id: Some(self.id.as_slice().to_vec()),
            target: None,
            closer_nodes,
            roundtrip_token: Some(self.token(&peer, &self.secrets.0[..]).as_bytes().to_vec()),
            command: None,
            error: None,
            value,
        };
        Ok(self.send_to(msg, peer)?)
    }

    /// Send an update message
    pub fn update(
        &mut self,
        cmd: Command,
        target: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Update.id(),
            rid: 0,
            to: Some(peer.encode()),
            id: Some(self.id.as_slice().to_vec()),
            target,
            closer_nodes: None,
            roundtrip_token,
            command: Some(cmd.to_string()),
            error: None,
            value,
        };
        Ok(self.send_to(msg, peer)?)
    }

    fn on_response(&mut self, recv: Message, peer: Peer) -> RpcEvent {
        if let Some(req) = self.pending_recv.remove(&recv.get_request_id()) {
            if let Some(ref id) = recv.id {
                if id.len() == 32 && Some(id) == req.message.id.as_ref() {
                    return RpcEvent::InResponse {
                        peer,
                        recv,
                        sent: req.message,
                    };
                }
            }
        }
        RpcEvent::InResponseBadId { peer, msg: recv }
    }

    /// A new `Message` was read from the socket.
    fn on_message(&mut self, mut msg: Message, rinfo: SocketAddr) -> Option<RpcEvent> {
        if let Some(ref id) = msg.id {
            if id.len() != 32 {
                // TODO Receive Error? clear waiting?
                return None;
            }
            // Force eph if older version
            if msg.version.unwrap_or_default() < VERSION {
                msg.id = None
            }
        }
        let peer = Peer::from(rinfo);

        match msg.get_type() {
            Ok(ty) => match ty {
                Type::Response => Some(self.on_response(msg, peer)),
                Type::Query => Some(RpcEvent::InRequest { peer, msg }),
                Type::Update => {
                    if let Some(ref rt) = msg.roundtrip_token {
                        if rt.as_slice() != self.token(&peer, &self.secrets.0).as_bytes()
                            && rt.as_slice() != self.token(&peer, &self.secrets.1).as_bytes()
                        {
                            None
                        } else {
                            Some(RpcEvent::InRequest { peer, msg })
                        }
                    } else {
                        None
                    }
                }
            },
            Err(_) => {
                // TODO handle unknown type?
                None
            }
        }
    }

    fn rotate_secrets(&mut self) {
        std::mem::swap(&mut self.secrets.0, &mut self.secrets.1);
        self.last_rotation = Instant::now()
    }

    /// Remove the matching request from the sending queue or stop waiting for a response if already sent.
    fn cancel(&mut self, rid: RequestId, error: Option<String>) -> Option<(Message, Peer)> {
        if let Some(s) = self
            .pending_send
            .iter()
            .position(|(msg, _)| msg.get_request_id() == rid)
        {
            self.pending_send.remove(s)
        } else {
            self.pending_recv
                .remove(&rid)
                .map(|req| (req.message, req.peer))
        }
    }
}

impl Stream for Io {
    type Item = RpcEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        // TODO check providers

        // flush pending send
        if let Some((message, peer)) = pin.pending_flush.take() {
            let socket = &mut pin.socket;
            pin_mut!(socket);
            if Sink::poll_ready(socket, cx).is_ready() {
                // TODO handle error
                pin.send_next_pending();

                // if we sent a query, we wait for a response
                if Ok(Type::Query) == message.get_type() {
                    let id = message.get_request_id();
                    pin.pending_recv.insert(
                        id,
                        Request {
                            message,
                            peer,
                            timestamp: Instant::now(),
                        },
                    );
                    return Poll::Ready(Some(RpcEvent::OutRequest { id }));
                } else {
                    return Poll::Ready(Some(RpcEvent::OutResponse { msg: message, peer }));
                }
            } else {
                pin.pending_flush = Some((message, peer));
            }
        } else {
            if let Err(err) = pin.send_next_pending() {
                return Poll::Ready(Some(RpcEvent::OutSocketErr { err }));
            }
        }

        // read from socket
        let socket = &mut pin.socket;
        pin_mut!(socket);
        match Stream::poll_next(socket, cx) {
            Poll::Ready(Some(Ok((msg, rinfo)))) => {
                if let Some(event) = pin.on_message(msg, rinfo) {
                    return Poll::Ready(Some(event));
                }
            }
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(RpcEvent::InSocketErr { err })),
            _ => {}
        }

        if pin.last_rotation + pin.rotation > Instant::now() {
            pin.rotate_secrets();
        }

        Poll::Pending
    }
}

/// Event generated by the DHT
pub enum RpcEvent {
    /// Udp Message sent.
    OutResponse { msg: Message, peer: Peer },
    /// A Request/query was sent
    OutRequest { id: RequestId },
    /// The Response to a sent Request
    InResponse {
        recv: Message,
        sent: Message,
        peer: Peer,
    },
    /// Response successfully read from socket.
    InRequest { msg: Message, peer: Peer },
    /// Error while start sending.
    OutSocketErr { err: io::Error },
    /// Failed to get a response for this request
    RequestTimeout {
        msg: Message,
        peer: Peer,
        sent: Instant,
    },
    /// Error while decoding from socket
    InMessageErr { err: io::Error, peer: Peer },
    /// Error while reading from socket
    InSocketErr { err: io::Error },
    /// `msg` id was invalid
    InResponseBadId { msg: Message, peer: Peer },
}

#[derive(Debug, Clone)]
pub struct Eviction {
    timeout: Duration,
}

impl Eviction {
    /// Remove all timeout requests
    fn poll(&self, store: &mut FnvHashMap<(), ()>) -> Poll<Option<Vec<Request>>> {
        unimplemented!()
    }
}
