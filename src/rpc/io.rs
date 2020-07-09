use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use blake2::crypto_mac::generic_array::{typenum::U64, GenericArray};
use blake2::{Blake2b, Digest};
use bytes::Bytes;
use fnv::FnvHashMap;
use futures::{
    pin_mut,
    task::{Context, Poll},
    Sink,
};
use log::debug;
use prost::Message as ProtoMessage;
use tokio::{net::UdpSocket, stream::Stream};
use tokio_util::{codec::Encoder, udp::UdpFramed};
use wasm_timer::Instant;

use crate::kbucket::Key;
use crate::rpc::fill_random_bytes;
use crate::rpc::message::Holepunch;
use crate::{
    kbucket::KeyBytes,
    peers::PeersEncoding,
    rpc::message::{Command, Message, Type},
    rpc::protocol::DhtRpcCodec,
    rpc::{Peer, RequestId},
};
use rand::Rng;
use std::ops::Deref;

pub const VERSION: u64 = 1;

const ROTATE_INTERVAL: u64 = 300_000;

pub struct Request<TUserData> {
    /// The message send
    message: Message,
    /// The remote peer
    peer: Peer,
    /// Timestamp when the request was sent
    timestamp: Instant,
    user_data: TUserData,
}

impl<TUserData> Request<TUserData> {
    fn into_event(self) -> Result<MessageEvent<TUserData>, Self> {
        if let Ok(ty) = self.message.get_type() {
            match ty {
                Type::Query => Ok(MessageEvent::Query {
                    msg: self.message,
                    peer: self.peer,
                    user_data: self.user_data,
                }),
                Type::Update => Ok(MessageEvent::Update {
                    msg: self.message,
                    peer: self.peer,
                    user_data: self.user_data,
                }),
                _ => Err(self),
            }
        } else {
            Err(self)
        }
    }
}

pub enum MessageEvent<TUserData> {
    Update {
        msg: Message,
        peer: Peer,
        user_data: TUserData,
    },
    Query {
        msg: Message,
        peer: Peer,
        user_data: TUserData,
    },
    Response {
        msg: Message,
        peer: Peer,
    },
    // TODO FireAndForget like Response?
}

impl<TUserData> MessageEvent<TUserData> {
    fn inner(&self) -> (&Message, &Peer) {
        match self {
            MessageEvent::Update { peer, msg, .. } => (msg, peer),
            MessageEvent::Query { peer, msg, .. } => (msg, peer),
            MessageEvent::Response { peer, msg } => (msg, peer),
        }
    }

    fn inner_mut(&mut self) -> (&mut Message, &mut Peer) {
        match self {
            MessageEvent::Update { peer, msg, .. } => (msg, peer),
            MessageEvent::Query { peer, msg, .. } => (msg, peer),
            MessageEvent::Response { peer, msg } => (msg, peer),
        }
    }

    fn into_inner(self) -> (Message, Peer) {
        match self {
            MessageEvent::Update { peer, msg, .. } => (msg, peer),
            MessageEvent::Query { peer, msg, .. } => (msg, peer),
            MessageEvent::Response { peer, msg } => (msg, peer),
        }
    }
}

pub struct IoHandler<TUserData> {
    id: Option<Key<Vec<u8>>>,
    socket: UdpFramed<DhtRpcCodec>,
    /// Messages to send
    pending_send: VecDeque<MessageEvent<TUserData>>,
    /// Current message
    pending_flush: Option<MessageEvent<TUserData>>,
    /// Sent requests we currently wait for a response
    pending_recv: FnvHashMap<RequestId, Request<TUserData>>,
    secrets: ([u8; 32], [u8; 32]),

    queued_events: VecDeque<IoHandlerEvent<TUserData>>,

    next_req_id: RequestId,

    rotation: Duration,
    last_rotation: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct IoConfig {
    pub rotation: Option<Duration>,
    pub secrets: Option<([u8; 32], [u8; 32])>,
}

impl<TUserData> IoHandler<TUserData>
where
    TUserData: fmt::Debug + Clone,
{
    pub fn new(
        id: Option<Key<Vec<u8>>>,
        socket: UdpSocket,
        config: IoConfig,
    ) -> IoHandler<TUserData> {
        let socket = UdpFramed::new(socket, DhtRpcCodec::default());

        let secrets = config.secrets.unwrap_or_else(|| {
            let mut k1 = [0; 32];
            let mut k2 = [0; 32];
            fill_random_bytes(&mut k1);
            fill_random_bytes(&mut k2);
            (k1, k2)
        });

        Self {
            id,
            socket,
            pending_send: Default::default(),
            pending_flush: None,
            pending_recv: Default::default(),
            secrets,
            queued_events: Default::default(),
            next_req_id: Self::random_id(),
            rotation: config
                .rotation
                .unwrap_or_else(|| Duration::from_millis(300_000)),
            last_rotation: Instant::now(),
        }
    }

    fn random_id() -> RequestId {
        use rand::Rng;
        RequestId(rand::thread_rng().gen())
    }

    pub(crate) fn msg_id(&self) -> Option<Vec<u8>> {
        self.id.as_ref().map(|k| k.preimage().clone())
    }

    /// Generate the next request id
    fn next_req_id(&mut self) -> RequestId {
        let rid = self.next_req_id;
        self.next_req_id = RequestId(self.next_req_id.0.wrapping_add(1));
        rid
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.get_ref().local_addr()
    }

    /// Generate a blake2 hash based on the peer's ip and the provided secret
    fn token(&self, peer: &Peer, secret: &[u8]) -> GenericArray<u8, U64> {
        let mut context = Blake2b::new();
        context.update(secret);
        context.update(peer.addr.ip().to_string().as_bytes());
        context.finalize()
    }

    fn holepunch(
        &mut self,
        mut msg: Message,
        peer: SocketAddr,
        referrer: SocketAddr,
        user_data: TUserData,
    ) {
        msg.version = Some(VERSION);
        msg.r#type = Type::Query.id();
        msg.to = Some(referrer.encode());
        if msg
            .set_holepunch(&Holepunch::with_to(peer.encode()))
            .is_err()
        {
            return;
        }
        self.send_message(MessageEvent::Query {
            msg,
            peer: Peer::from(referrer),
            user_data,
        })
    }

    /// Start sending a new message if any is pending
    fn send_next_pending(&mut self) -> io::Result<()> {
        if let Some(event) = self.pending_send.pop_front() {
            let (msg, peer) = event.inner();
            let mut buf = Vec::with_capacity(msg.encoded_len());
            msg.encode(&mut buf)?;
            let socket = &mut self.socket;
            Sink::start_send(Pin::new(&mut self.socket), (buf, peer.addr.clone()))?;

            self.pending_flush = Some(event);
        }
        Ok(())
    }

    /// Send the message to the peer
    ///
    /// If we're currently busy with sending another message, the message gets queued in
    fn send_to(&mut self, event: MessageEvent<TUserData>) -> anyhow::Result<()> {
        if self.pending_flush.is_none() {
            let (msg, peer) = event.inner();
            let mut buffer = Vec::with_capacity(msg.encoded_len());
            msg.encode(&mut buffer)?;
            Sink::start_send(Pin::new(&mut self.socket), (buffer, peer.addr.clone()))?;
            self.pending_flush = Some(event);
        } else {
            self.pending_send.push_back(event);
        }
        Ok(())
    }

    fn request(&mut self, mut ev: MessageEvent<TUserData>) {
        let (msg, peer) = ev.inner_mut();
        msg.rid = self.next_req_id().0;

        if msg.is_holepunch() && peer.referrer.is_some() {
            match &ev {
                MessageEvent::Update {
                    msg,
                    peer,
                    user_data,
                }
                | MessageEvent::Query {
                    msg,
                    peer,
                    user_data,
                } => self.holepunch(
                    msg.clone(),
                    peer.addr,
                    peer.referrer.unwrap(),
                    user_data.clone(),
                ),
                _ => {}
            }
        }
        self.pending_send.push_back(ev)
    }

    /// Send a new Query message
    pub fn query(
        &mut self,
        cmd: Command,
        target: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        peer: Peer,
        user_data: TUserData,
    ) {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Query.id(),
            rid: 0,
            to: Some(peer.encode()),
            id: self.msg_id(),
            target,
            closer_nodes: None,
            roundtrip_token: None,
            command: Some(cmd.to_string()),
            error: None,
            value,
        };

        self.request(MessageEvent::Query {
            msg,
            peer,
            user_data,
        })
    }

    pub fn error(
        &mut self,
        request: Message,
        error: Option<String>,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<u8>>,
        peer: Peer,
    ) {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Response.id(),
            rid: request.rid,
            to: Some(peer.encode()),
            id: self.msg_id(),
            target: None,
            closer_nodes,
            roundtrip_token: None,
            command: None,
            error,
            value,
        };
        self.pending_send
            .push_back(MessageEvent::Response { msg, peer })
    }

    pub fn response(
        &mut self,
        request: Message,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<u8>>,
        peer: Peer,
    ) {
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Response.id(),
            rid: request.rid,
            to: Some(peer.encode()),
            id: self.msg_id(),
            target: None,
            closer_nodes,
            roundtrip_token: Some(self.token(&peer, &self.secrets.0[..]).to_vec()),
            command: None,
            error: None,
            value,
        };
        self.pending_send
            .push_back(MessageEvent::Response { msg, peer })
    }

    pub fn send_message(&mut self, msg: MessageEvent<TUserData>) {
        self.pending_send.push_back(msg)
    }

    /// Send an update message
    pub fn update(
        &mut self,
        cmd: Command,
        target: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
        user_data: TUserData,
    ) {
        // TODO just push to queue
        let msg = Message {
            version: Some(VERSION),
            r#type: Type::Update.id(),
            rid: 0,
            to: Some(peer.encode()),
            id: self.msg_id(),
            target,
            closer_nodes: None,
            roundtrip_token,
            command: Some(cmd.to_string()),
            error: None,
            value,
        };

        self.request(MessageEvent::Update {
            msg,
            peer,
            user_data,
        });
    }

    fn on_response(&mut self, recv: Message, peer: Peer) -> IoHandlerEvent<TUserData> {
        if let Some(req) = self.pending_recv.remove(&recv.get_request_id()) {
            if let Some(ref id) = recv.id {
                if id.len() == 32 {
                    return IoHandlerEvent::InResponse {
                        peer,
                        resp: recv,
                        req: req.message,
                        user_data: req.user_data,
                    };
                }
            }
        }
        IoHandlerEvent::InResponseBadId { peer, msg: recv }
    }

    /// A new `Message` was read from the socket.
    fn on_message(
        &mut self,
        mut msg: Message,
        rinfo: SocketAddr,
    ) -> Option<IoHandlerEvent<TUserData>> {
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
                Type::Query => Some(IoHandlerEvent::InRequest {
                    peer,
                    msg,
                    ty: Type::Update,
                }),
                Type::Update => {
                    if let Some(ref rt) = msg.roundtrip_token {
                        if rt.as_slice() != self.token(&peer, &self.secrets.0).deref()
                            && rt.as_slice() != self.token(&peer, &self.secrets.1).deref()
                        {
                            None
                        } else {
                            Some(IoHandlerEvent::InRequest {
                                peer,
                                msg,
                                ty: Type::Update,
                            })
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
    fn cancel(&mut self, rid: RequestId, error: Option<String>) -> Option<MessageEvent<TUserData>> {
        if let Some(s) = self
            .pending_send
            .iter()
            .position(|e| e.inner().0.get_request_id() == rid)
        {
            self.pending_send.remove(s)
        } else {
            self.pending_recv
                .remove(&rid)
                .and_then(|req| req.into_event().ok())
        }
    }
}

impl<TUserData: Unpin + fmt::Debug + Clone> Stream for IoHandler<TUserData> {
    type Item = IoHandlerEvent<TUserData>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        // TODO check providers

        // flush pending send
        if let Some(ev) = pin.pending_flush.take() {
            if Sink::poll_ready(Pin::new(&mut pin.socket), cx).is_ready() {
                debug!("sink ready to send {:?}", ev.inner());
                pin.send_next_pending();

                return match ev {
                    MessageEvent::Update {
                        msg,
                        peer,
                        user_data,
                    }
                    | MessageEvent::Query {
                        msg,
                        peer,
                        user_data,
                    } => {
                        let id = msg.get_request_id();
                        pin.pending_recv.insert(
                            id,
                            Request {
                                message: msg,
                                peer,
                                timestamp: Instant::now(),
                                user_data,
                            },
                        );
                        return Poll::Ready(Some(IoHandlerEvent::OutRequest { id }));
                    }
                    MessageEvent::Response { msg, peer } => {
                        Poll::Ready(Some(IoHandlerEvent::OutResponse { msg, peer }))
                    }
                };
            } else {
                pin.pending_flush = Some(ev);
            }
        } else {
            if let Err(err) = pin.send_next_pending() {
                return Poll::Ready(Some(IoHandlerEvent::OutSocketErr { err }));
            }
        }

        // read from socket
        match Stream::poll_next(Pin::new(&mut pin.socket), cx) {
            Poll::Ready(Some(Ok((msg, rinfo)))) => {
                debug!("read message {:?}", msg);
                if let Some(event) = pin.on_message(msg, rinfo) {
                    debug!("return handler event {:?}", event);
                    return Poll::Ready(Some(event));
                }
            }
            Poll::Ready(Some(Err(err))) => {
                debug!("read error {:?}", err);
                return Poll::Ready(Some(IoHandlerEvent::InSocketErr { err }));
            }
            Poll::Ready(None) => debug!("Stream read none"),
            Poll::Pending => debug!("Stream read pending"),
        }

        if pin.last_rotation + pin.rotation > Instant::now() {
            pin.rotate_secrets();
        }

        Poll::Pending
    }
}

/// Event generated by the IO handler
#[derive(Debug)]
pub enum IoHandlerEvent<TUserData> {
    /// Udp Message sent.
    OutResponse { msg: Message, peer: Peer },
    /// A Request/query was sent
    OutRequest { id: RequestId },
    /// The Response to a sent Request
    InResponse {
        req: Message,
        resp: Message,
        peer: Peer,
        user_data: TUserData,
    },
    /// Response successfully read from socket.
    InRequest { msg: Message, peer: Peer, ty: Type },
    /// Error while start sending.
    OutSocketErr { err: io::Error },
    /// Failed to get a response for this request
    RequestTimeout {
        msg: Message,
        peer: Peer,
        sent: Instant,
        user_data: TUserData,
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
