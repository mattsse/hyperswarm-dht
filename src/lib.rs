#![allow(unused)]

use core::cmp;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::pin::Pin;
use std::time::Duration;

use bytes::Buf;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use either::Either;
use fnv::FnvHashMap;
use futures::task::{Context, Poll};
use futures::Stream;
use prost::Message as ProstMessage;
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use smallvec::alloc::collections::VecDeque;

use crate::dht_proto::{encode_input, Mutable, PeersInput, PeersOutput};
use crate::lru::{CacheKey, PeerCache};
use crate::peers::{decode_local_peers, decode_peers, PeersEncoding};
use crate::rpc::message::{Message, Type};
use crate::rpc::query::{CommandQuery, CommandQueryResponse, QueryId, QueryStats};
pub use crate::rpc::{DhtConfig, IdBytes, Peer, PeerId};
use crate::rpc::{RequestOk, Response, ResponseOk, RpcDht, RpcDhtEvent};
use crate::store::{StorageEntry, StorageKey, Store, PUT_VALUE_MAX_SIZE};

mod dht_proto {
    use prost::Message;

    include!(concat!(env!("OUT_DIR"), "/dht_pb.rs"));

    #[inline]
    pub fn encode_input(peers: &PeersInput) -> Vec<u8> {
        let mut buf = Vec::with_capacity(peers.encoded_len());
        // vec has sufficient capacity up to usize::MAX
        peers.encode(&mut buf).unwrap();
        buf
    }
}

pub mod crypto;
pub mod kbucket;
pub mod lru;
pub mod peers;
pub mod rpc;
pub mod store;

const EPH_AFTER: u64 = 1000 * 60 * 20;

const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "bootstrap1.hyperdht.org:49737",
    "bootstrap2.hyperdht.org:49737",
    "bootstrap3.hyperdht.org:49737",
];

pub(crate) const ERR_INVALID_INPUT: &str = "ERR_INVALID_INPUT";

pub const MUTABLE_STORE_CMD: &str = "mutable-store";
pub const IMMUTABLE_STORE_CMD: &str = "immutable-store";
pub const PEERS_CMD: &str = "peers";

pub struct HyperDht {
    /// The underlying Rpc DHT including IO
    inner: RpcDht,
    /// Map to track the queries currently in progress
    queries: FnvHashMap<QueryId, QueryStreamType>,
    adaptive: bool,
    /// Cache for known peers
    peers: PeerCache,
    /// Storage for the mutable/immutable values
    store: Store,
    /// Queued events to return when being polled.
    queued_events: VecDeque<HyperDhtEvent>,
}

impl HyperDht {
    /// Create a new DHT based on the configuration
    pub async fn with_config(mut config: DhtConfig) -> io::Result<Self> {
        config = config.register_commands(&[MUTABLE_STORE_CMD, IMMUTABLE_STORE_CMD, PEERS_CMD]);

        if config.bootstrap_nodes().is_none() {
            config = config.set_bootstrap_nodes(&DEFAULT_BOOTSTRAP[..]);
        }

        Ok(Self {
            adaptive: config.adaptive,
            queries: Default::default(),
            inner: RpcDht::with_config(config).await?,
            // peer cache with 25 min timeout
            peers: PeerCache::new(65536, Duration::from_secs(60 * 25)),
            store: Store::new(5000),
            queued_events: Default::default(),
        })
    }

    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn tally(&mut self, only_ip: bool) {
        unimplemented!()
    }

    /// Handle an incoming requests for the registered commands and reply.
    fn on_command(&mut self, q: CommandQuery) {
        match q.command.as_str() {
            MUTABLE_STORE_CMD => {
                let resp = self.store.on_command_mut(q);
                self.inner.reply_command(resp)
            }
            IMMUTABLE_STORE_CMD => {
                let resp = self.store.on_command(q);
                self.inner.reply_command(resp)
            }
            PEERS_CMD => self.on_peers(q),
            c => {
                let command = c.to_string();
                let resp = CommandQueryResponse::from(q);
                self.queued_events
                    .push_back(HyperDhtEvent::CustomCommandQuery {
                        command,
                        msg: Box::new(resp.msg),
                        peer: resp.peer,
                    })
            }
        }
    }

    /// Fetch a mutable value from the DHT.
    ///
    /// if the querying node already has the immutable value then there's no need to query the dht. In that case [`Either::Right`] is returned containing the key and the corresponding immutable value.
    pub fn get_immutable(
        &mut self,
        key: impl Into<IdBytes>,
    ) -> Either<QueryId, (IdBytes, Vec<u8>)> {
        let key = key.into();

        if let Some(value) = self
            .store
            .get(&StorageKey::Immutable(key.clone()))
            .and_then(StorageEntry::as_immutable)
            .cloned()
        {
            // value already present
            return Either::Right((key, value));
        }

        // query the DHT
        let query_id = self
            .inner
            .query(IMMUTABLE_STORE_CMD, kbucket::Key::new(key.clone()), None);

        self.queries.insert(
            query_id,
            QueryStreamType::GetImmutable(GetResult::new(key, query_id)),
        );

        Either::Left(query_id)
    }

    /// Fetch a mutable value from the DHT.
    pub fn get_mutable(&mut self, get: impl Into<GetOpts>) -> Result<QueryId, ()> {
        let get = get.into();
        if get.salt.as_ref().map(|s| s.len() > 64).unwrap_or_default() {
            // salt size must be no greater than 64 bytes
            return Err(());
        }

        let value = Mutable {
            value: None,
            signature: None,
            seq: Some(get.seq),
            salt: get.salt,
        };
        let mut buf = Vec::with_capacity(value.encoded_len());
        value.encode(&mut buf).unwrap();

        // query the DHT
        let query_id = self.inner.query(
            MUTABLE_STORE_CMD,
            kbucket::Key::new(get.key.clone()),
            Some(buf),
        );

        self.queries.insert(
            query_id,
            QueryStreamType::GetMutable {
                get: GetResult::new(get.key, query_id),
                value,
            },
        );
        Ok(query_id)
    }

    /// Store an immutable value in the DHT.
    pub fn put_immutable(&mut self, value: &[u8]) -> Result<QueryId, ()> {
        let value = value.to_vec();
        if value.len() > PUT_VALUE_MAX_SIZE {
            return Err(());
        }
        let key = crypto::hash_id(&value);
        // set locally for easy cached retrieval
        self.store.put_immutable(key.clone(), value.clone());

        let query_id = self.inner.update(
            IMMUTABLE_STORE_CMD,
            kbucket::Key::new(key.clone()),
            Some(value),
        );

        self.queries
            .insert(query_id, QueryStreamType::PutImmutable { query_id, key });
        Ok(query_id)
    }

    /// Store a mutable value in the DHT.
    pub fn put_mutable(&mut self, value: &[u8], opts: PutOpts) -> Result<QueryId, ()> {
        let value = value.to_vec();
        if value.len() > PUT_VALUE_MAX_SIZE {
            return Err(());
        }

        let value = opts.mutable(value.to_vec());
        let mut buf = Vec::with_capacity(value.encoded_len());
        value.encode(&mut buf).unwrap();

        let key = opts.id();
        self.store
            .put_mutable(Store::get_mut_key(&value, &key), value);
        let query_id = self
            .inner
            .update(MUTABLE_STORE_CMD, kbucket::Key::new(key), Some(buf));

        self.queries.insert(
            query_id,
            QueryStreamType::PutMutable {
                query_id,
                opts: Box::new(opts),
            },
        );

        Ok(query_id)
    }

    /// Callback for an incoming `peers` command query
    fn on_peers(&mut self, mut query: CommandQuery) {
        // decode the received value
        if let Some(ref val) = query.value {
            if let Ok(peer) = PeersInput::decode(&**val) {
                // callback
                let port = peer
                    .port
                    .and_then(|port| u16::try_from(port).ok())
                    .unwrap_or_else(|| query.peer.addr.port());

                if let IpAddr::V4(host) = query.peer.addr.ip() {
                    let from = SocketAddr::V4(SocketAddrV4::new(host, port));

                    let remote_cache = CacheKey::Remote(query.target.clone());

                    let local_cache = peer.local_address.as_ref().and_then(|l| {
                        if l.len() == 6 {
                            let prefix: [u8; 2] = l[0..2].try_into().unwrap();
                            let suffix: [u8; 4] = l[2..].try_into().unwrap();
                            Some((
                                CacheKey::Local {
                                    id: query.target.clone(),
                                    prefix,
                                },
                                suffix,
                            ))
                        } else {
                            None
                        }
                    });

                    if query.ty == Type::Query {
                        let local_peers = if let Some((local_cache, suffix)) = local_cache {
                            self.peers.get(&local_cache).and_then(|addrs| {
                                addrs.iter_locals().map(|locals| {
                                    locals
                                        .filter(|s| **s != suffix)
                                        .flat_map(|s| s.iter())
                                        .cloned()
                                        .take(32)
                                        .collect::<Vec<_>>()
                                })
                            })
                        } else {
                            None
                        };

                        let peers = if let Some(remotes) = self
                            .peers
                            .get(&remote_cache)
                            .and_then(|addrs| addrs.remotes())
                        {
                            let num = cmp::min(
                                remotes.len(),
                                128 - local_peers.as_ref().map(|l| l.len()).unwrap_or_default(),
                            );
                            let mut buf = Vec::with_capacity(num * 6);

                            for addr in remotes.iter().filter(|addr| **addr != from).take(num) {
                                if let IpAddr::V4(ip) = addr.ip() {
                                    buf.extend_from_slice(&ip.octets()[..]);
                                    buf.extend_from_slice(&addr.port().to_be_bytes()[..]);
                                }
                            }
                            Some(buf)
                        } else {
                            None
                        };

                        let output = PeersOutput { peers, local_peers };
                        let mut buf = Vec::with_capacity(output.encoded_len());

                        // fits safe in vec
                        output.encode(&mut buf).unwrap();
                        query.value = Some(buf);
                        self.inner.reply_command(query);
                        return;
                    }

                    if peer.unannounce.unwrap_or_default() {
                        // remove from cache
                        self.peers.remove_addr(&remote_cache, from);
                        if let Some(local) = local_cache {
                            self.peers.remove_addr(&local.0, local.1);
                        }
                    } else {
                        // add the new record
                        self.peers.insert(remote_cache, from);
                        if let Some(local) = local_cache {
                            self.peers.insert(local.0, local.1);
                        }
                    }
                }
                let _ = query.value.take();
                self.inner.reply_command(query);
            }
        }
    }

    /// Look for peers in the DHT on the given topic.
    pub fn lookup(&mut self, opts: impl Into<QueryOpts>) -> QueryId {
        let opts = opts.into();

        let peers = PeersInput {
            port: opts.port,
            local_address: opts.local_addr_encoded(),
            unannounce: None,
        };
        let buf = encode_input(&peers);

        let id = self
            .inner
            .query(PEERS_CMD, kbucket::Key::new(opts.topic.clone()), Some(buf));
        self.queries.insert(
            id,
            QueryStreamType::LookUp(QueryStreamInner::new(opts.topic, opts.local_addr)),
        );
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
        let buf = encode_input(&peers);

        let id = self.inner.query_and_update(
            PEERS_CMD,
            kbucket::Key::new(opts.topic.clone()),
            Some(buf),
        );
        self.queries.insert(
            id,
            QueryStreamType::Announce(QueryStreamInner::new(opts.topic, opts.local_addr)),
        );
        id
    }

    pub fn unannounce(&mut self, opts: impl Into<QueryOpts>) -> QueryId {
        let opts = opts.into();

        let peers = PeersInput {
            port: opts.port,
            local_address: opts.local_addr_encoded(),
            unannounce: Some(true),
        };
        let buf = encode_input(&peers);

        let id = self
            .inner
            .update(PEERS_CMD, kbucket::Key::new(opts.topic.clone()), Some(buf));
        self.queries.insert(
            id,
            QueryStreamType::UnAnnounce(QueryStreamInner::new(opts.topic, opts.local_addr)),
        );
        id
    }

    fn inject_response(&mut self, resp: Response) {
        if let Some(query) = self.queries.get_mut(&resp.query) {
            match query {
                QueryStreamType::LookUp(inner)
                | QueryStreamType::Announce(inner)
                | QueryStreamType::UnAnnounce(inner) => inner.inject_response(resp),
                QueryStreamType::GetImmutable(get) => {
                    if let Some(value) = resp.value {
                        let key = crypto::hash_id(&value);
                        if get.key == key {
                            self.store.put_immutable(key, value.clone());
                            get.responses.push(PeerResponseItem {
                                peer: resp.peer,
                                peer_id: resp.peer_id,
                                value,
                            })
                        }
                    }
                }
                QueryStreamType::GetMutable { get, value } => {
                    if let Some(result) = resp.decode_value::<Mutable>() {
                        if result.seq.unwrap_or_default() >= value.seq.unwrap_or_default()
                            && store::verify(&get.key, &result).is_ok()
                        {
                            self.store
                                .put_mutable(Store::get_mut_key(&result, &get.key), result.clone());

                            get.responses.push(PeerResponseItem {
                                peer: resp.peer,
                                peer_id: resp.peer_id,
                                value: result,
                            })
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // A query was completed
    fn query_finished(&mut self, id: QueryId) {
        if let Some(query) = self.queries.remove(&id) {
            self.queued_events.push_back(query.finalize(id))
        }
    }
}

impl Stream for HyperDht {
    type Item = HyperDhtEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        loop {
            // Drain queued events first.
            if let Some(event) = pin.queued_events.pop_front() {
                return Poll::Ready(Some(event));
            }

            while let Poll::Ready(Some(ev)) = Stream::poll_next(Pin::new(&mut pin.inner), cx) {
                match ev {
                    RpcDhtEvent::RequestResult(Ok(RequestOk::CustomCommandRequest { query })) => {
                        pin.on_command(query)
                    }
                    RpcDhtEvent::ResponseResult(Ok(ResponseOk::Response(resp))) => {
                        pin.inject_response(resp)
                    }
                    RpcDhtEvent::Bootstrapped { stats } => {
                        return Poll::Ready(Some(HyperDhtEvent::Bootstrapped { stats }))
                    }
                    RpcDhtEvent::QueryResult {
                        id,
                        cmd: _,
                        stats: _,
                    } => pin.query_finished(id),
                    _ => {}
                }
            }

            // No immediate event was produced as a result of the DHT.
            // If no new events have been queued either, signal `Pending` to
            // be polled again later.
            if pin.queued_events.is_empty() {
                return Poll::Pending;
            }
        }
    }
}
#[derive(Debug)]
pub struct PutOpts {
    /// The crypto to identification and offline signing of the value
    pub key: PutKey,
    /// A number which should be increased every time put is passed a new value for the same keypair
    pub seq: u64,
    /// If supplied it will salt the signature used to verify mutable values.
    pub salt: Option<Vec<u8>>,
}

impl PutOpts {
    pub fn new(key: PutKey) -> Self {
        Self {
            key,
            seq: 0,
            salt: None,
        }
    }

    fn mutable(&self, value: Vec<u8>) -> Mutable {
        use ed25519_dalek::ed25519::signature::Signature;
        let signature = match &self.key {
            PutKey::KeyPair(kp) => {
                crypto::sign(&kp.public, &kp.secret, &value, self.salt.as_ref(), self.seq)
                    .as_bytes()
                    .to_vec()
            }
            PutKey::Signature((_, sig)) => sig.as_bytes().to_vec(),
        };

        Mutable {
            value: Some(value),
            signature: Some(signature),
            seq: Some(self.seq),
            salt: self.salt.clone(),
        }
    }

    fn id(&self) -> IdBytes {
        match &self.key {
            PutKey::KeyPair(kp) => (&kp.public).into(),
            PutKey::Signature((pk, _)) => pk.into(),
        }
    }

    pub fn with_keypair(keypair: Keypair) -> Self {
        Self {
            key: PutKey::KeyPair(keypair),
            seq: 0,
            salt: None,
        }
    }

    pub fn with_pk_and_signature(pk: PublicKey, signature: Signature) -> Self {
        Self {
            key: PutKey::Signature((pk, signature)),
            seq: 0,
            salt: None,
        }
    }

    pub fn seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    pub fn salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(salt);
        self
    }
}

#[derive(Debug)]
pub enum PutKey {
    KeyPair(Keypair),
    /// Use a signature instead of the key pair's private key
    Signature((PublicKey, Signature)),
}

#[derive(Debug, Clone)]
pub struct GetOpts {
    /// The public key
    pub key: IdBytes,
    /// A number which will only return values with corresponding seq values that are greater than or equal to the supplied seq option
    pub seq: u64,
    /// If supplied it will salt the signature used to verify mutable values.
    pub salt: Option<Vec<u8>>,
}

impl GetOpts {
    pub fn new(key: impl Into<IdBytes>) -> Self {
        Self {
            key: key.into(),
            seq: 0,
            salt: None,
        }
    }

    pub fn with_seq(key: impl Into<IdBytes>, seq: u64) -> Self {
        Self {
            key: key.into(),
            seq,
            salt: None,
        }
    }

    pub fn salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(salt);
        self
    }
}

impl<T: Into<IdBytes>> From<T> for GetOpts {
    fn from(key: T) -> Self {
        GetOpts::new(key)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryOpts {
    /// The topic to announce
    pub topic: IdBytes,
    /// Explicitly set the port you want to announce. Per default the UDP socket port is announced.
    pub port: Option<u32>,
    /// Optionally announce a LAN address as well. Only people with the same public IP as you will get these when doing a lookup
    pub local_addr: Option<SocketAddr>,
}

impl QueryOpts {
    fn local_addr_encoded(&self) -> Option<Vec<u8>> {
        self.local_addr.as_ref().map(|addr| addr.encode())
    }

    pub fn new(topic: impl Into<IdBytes>) -> Self {
        Self {
            topic: topic.into(),
            port: None,
            local_addr: None,
        }
    }

    pub fn port(mut self, port: u32) -> Self {
        self.port = Some(port);
        self
    }

    pub fn local_addr(mut self, local_addr: impl ToSocketAddrs) -> Self {
        self.local_addr = local_addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.next());
        self
    }
}

impl From<&PublicKey> for QueryOpts {
    fn from(key: &PublicKey) -> Self {
        Self {
            topic: key.into(),
            port: None,
            local_addr: None,
        }
    }
}

impl From<&GenericArray<u8, U32>> for QueryOpts {
    fn from(digest: &GenericArray<u8, U32>) -> Self {
        Self {
            topic: digest.as_slice().try_into().expect("Wrong length"),
            port: None,
            local_addr: None,
        }
    }
}

impl From<IdBytes> for QueryOpts {
    fn from(topic: IdBytes) -> Self {
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

#[derive(Debug)]
pub enum HyperDhtEvent {
    /// The dht is now bootstrapped
    Bootstrapped {
        /// Execution statistics from the bootstrap query.
        stats: QueryStats,
    },
    /// The result of [`HyperDht::announce`].
    AnnounceResult {
        peers: Vec<Peers>,
        /// The announced topic.
        topic: IdBytes,
        /// Tracking id of the query
        query_id: QueryId,
    },
    /// The result of [`HyperDht::lookup`].
    LookupResult {
        /// All responses
        lookup: Lookup,
        /// /// Tracking id of the query
        query_id: QueryId,
    },
    /// The result of [`HyperDht::unannounce`].
    UnAnnounceResult {
        peers: Vec<Peers>,
        topic: IdBytes,
        /// Tracking id of the query
        query_id: QueryId,
    },
    /// The result of [`HyperDht::put_immutable`].
    PutImmutableResult {
        /// The generated key (hash for that value)
        key: IdBytes,
        /// Tracking id of the query
        query_id: QueryId,
    },
    /// The result of [`HyperDht::put_mutable`].
    PutMutableResult {
        /// The options used to sign the value.
        opts: Box<PutOpts>,
        /// Tracking id of the query
        query_id: QueryId,
    },
    /// The result of [`HyperDht::get_immutable`].
    GetImmutableResult(GetResult<Vec<u8>>),
    /// The result of [`HyperDht::get_mutable`].
    GetMutableResult(GetResult<Mutable>),
    /// Received a query with a custom command that is not automatically handled by the DHT
    CustomCommandQuery {
        /// The unknown command
        command: String,
        /// The message we received from the peer.
        msg: Box<Message>,
        /// The peer the message originated from.
        peer: Peer,
    },
}

#[derive(Debug)]
pub struct GetResult<T: fmt::Debug> {
    /// The identifier for the value
    pub key: IdBytes,
    /// All matching immutable values from the DHT together with the id of the responding node
    pub responses: Vec<PeerResponseItem<T>>,
    /// Tracking id of the query
    pub query_id: QueryId,
}

impl<T: fmt::Debug> GetResult<T> {
    fn new(key: IdBytes, query_id: QueryId) -> Self {
        Self {
            key,
            responses: Vec::new(),
            query_id,
        }
    }

    /// Returns an iterator over all received values
    pub fn values<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        self.responses.iter().map(|r| &r.value)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }
}

#[derive(Debug)]
pub struct PeerResponseItem<T: fmt::Debug> {
    pub peer: SocketAddr,
    pub peer_id: Option<IdBytes>,
    pub value: T,
}

/// Result of a [`HyperDht::lookup`] query.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// The hash to lookup
    pub topic: IdBytes,
    /// The gathered responses
    pub peers: Vec<Peers>,
}

impl Lookup {
    /// Returns an iterator over all the nodes that sent data for this look
    pub fn origins<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a SocketAddr, Option<&'a IdBytes>)> + 'a {
        self.peers
            .iter()
            .map(|peer| (&peer.node, peer.peer_id.as_ref()))
    }

    /// Returns an iterator over all remote peers that announced the topic hash
    pub fn remotes<'a>(&'a self) -> impl Iterator<Item = &'a SocketAddr> + 'a {
        self.peers.iter().flat_map(|peer| peer.peers.iter())
    }

    /// Returns an iterator over all LAN peers that announced the topic hash
    pub fn locals<'a>(&'a self) -> impl Iterator<Item = &'a SocketAddr> + 'a {
        self.peers.iter().flat_map(|peer| peer.local_peers.iter())
    }

    /// Returns an iterator over all peers (remote and LAN) that announced the topic hash.
    pub fn all_peers<'a>(&'a self) -> impl Iterator<Item = &'a SocketAddr> + 'a {
        self.peers
            .iter()
            .flat_map(|peer| peer.peers.iter().chain(peer.local_peers.iter()))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// A Response to a query request from a peer
#[derive(Debug, Clone)]
pub struct Peers {
    /// The DHT node that is returning this data
    pub node: SocketAddr,
    /// The id of the `peer` if available
    pub peer_id: Option<IdBytes>,
    /// List of peers that announced the topic hash
    pub peers: Vec<SocketAddr>,
    /// List of LAN peers that announced the topic hash
    pub local_peers: Vec<SocketAddr>,
}

/// Type to keep track of the responses for queries in progress.
#[derive(Debug)]
enum QueryStreamType {
    LookUp(QueryStreamInner),
    Announce(QueryStreamInner),
    UnAnnounce(QueryStreamInner),
    PutImmutable {
        query_id: QueryId,
        key: IdBytes,
    },
    PutMutable {
        query_id: QueryId,
        /// How to verify the proof
        opts: Box<PutOpts>,
    },
    GetImmutable(GetResult<Vec<u8>>),
    GetMutable {
        get: GetResult<Mutable>,
        value: Mutable,
    },
}

impl QueryStreamType {
    fn finalize(self, query_id: QueryId) -> HyperDhtEvent {
        match self {
            QueryStreamType::LookUp(inner) => HyperDhtEvent::LookupResult {
                lookup: Lookup {
                    peers: inner.responses,
                    topic: inner.topic,
                },
                query_id,
            },
            QueryStreamType::Announce(inner) => HyperDhtEvent::AnnounceResult {
                peers: inner.responses,
                topic: inner.topic,
                query_id,
            },
            QueryStreamType::UnAnnounce(inner) => HyperDhtEvent::UnAnnounceResult {
                peers: inner.responses,
                topic: inner.topic,
                query_id,
            },
            QueryStreamType::PutImmutable { query_id, key } => {
                HyperDhtEvent::PutImmutableResult { query_id, key }
            }
            QueryStreamType::GetImmutable(get) => HyperDhtEvent::GetImmutableResult(get),
            QueryStreamType::GetMutable { get, .. } => HyperDhtEvent::GetMutableResult(get),
            QueryStreamType::PutMutable { query_id, opts } => {
                HyperDhtEvent::PutMutableResult { query_id, opts }
            }
        }
    }
}

#[derive(Debug)]
struct QueryStreamInner {
    topic: IdBytes,
    responses: Vec<Peers>,
    local_address: Option<SocketAddr>,
}

impl QueryStreamInner {
    fn new(topic: IdBytes, local_address: Option<SocketAddr>) -> Self {
        Self {
            topic,
            responses: Vec::new(),
            local_address,
        }
    }

    /// Store the decoded peers from the `Response` value
    fn inject_response(&mut self, resp: Response) {
        if let Some(val) = resp
            .value
            .as_ref()
            .and_then(|val| PeersOutput::decode(val.as_slice()).ok())
        {
            let peers = val.peers.as_ref().map(decode_peers).unwrap_or_default();

            let local_peers = val
                .local_peers
                .as_ref()
                .and_then(|buf| {
                    if let Some(SocketAddr::V4(addr)) = self.local_address {
                        Some(decode_local_peers(&addr, buf))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            if peers.is_empty() && local_peers.is_empty() {
                return;
            }
            self.responses.push(Peers {
                node: resp.peer,
                peer_id: resp.peer_id,
                peers,
                local_peers,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use async_std::net::Ipv4Addr;
    use futures::{FutureExt, SinkExt, StreamExt};

    use super::*;
    use crate::store::verify;
    use futures::future::FusedFuture;

    macro_rules! spawn_dhts {
        ($num:expr, $bs:expr) => {
            spawn_dhts!($num, $bs, false)
        };
        ($num:expr, $bs:expr, $eph:expr) => {{
            for _ in 0usize..$num {
                let mut dht = HyperDht::with_config(
                    DhtConfig::default()
                        .set_bootstrap_nodes($bs)
                        .set_ephemeral($eph),
                )
                .await?;
                // wait until this dht is bootstrapped
                match dht.next().await {
                    Some(HyperDhtEvent::Bootstrapped { .. }) => {}
                    _ => panic!("expected bootstrap result first"),
                }
                async_std::task::spawn(async move {
                    loop {
                        // process each incoming message
                        dht.next().await;
                    }
                });
            }
        }};
    }

    macro_rules! bootstrap_dht {
        () => {
            bootstrap_dht!(true)
        };
        ($eph:expr) => {{
            let mut bs = HyperDht::with_config(
                DhtConfig::default()
                    .empty_bootstrap_nodes()
                    .set_ephemeral($eph),
            )
            .await?;
            let addr = bs.local_addr()?;
            async_std::task::spawn(async move {
                loop {
                    // process each incoming message
                    bs.next().await;
                }
            });
            addr
        }};
    }

    #[async_std::test]
    async fn mutable_put_get() -> Result<(), Box<dyn std::error::Error>> {
        use futures::select;
        // create an ephemeral bootstrap node
        let bs_addr = bootstrap_dht!();
        // spawn some nodes bootstrapped with `bs`
        let num_spawned = 10;
        spawn_dhts!(num_spawned, &[bs_addr]);

        // the payloads used for the puts
        let hello = b"hello friend!";
        let bye = b"goodbye friend!";

        // sign the `Mutable`s with keypair
        let opts = PutOpts::with_keypair(crypto::keypair());
        let key = opts.id();

        let mut a =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;
        a.next().await;

        // 1. node `a` will put the value on the DHT
        a.put_mutable(hello, opts);

        let mut opts = match a.next().await {
            Some(HyperDhtEvent::PutMutableResult { opts, .. }) => Some(*opts),
            _ => panic!("expected result for the mutable value"),
        };

        // channel used to signal from b -> a that b finished another put_mutable
        let (mut tx, mut rx) = futures::channel::mpsc::channel(0);

        let mut b =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;

        // 2. node `b` queries the DHT for the value
        b.get_mutable(key.clone());
        async_std::task::spawn(async move {
            loop {
                if let Some(event) = b.next().await {
                    match event {
                        HyperDhtEvent::GetMutableResult(get) => {
                            // expected answers from every non ephemeral node `num_spawned` + `a`
                            assert_eq!(get.len(), num_spawned + 1);
                            let expected_val = Some(hello.to_vec());
                            assert!(get.values().all(|mutable| mutable.value == expected_val));

                            let mut opts = opts.take().unwrap();
                            // seq must be incremented when updating immutable data
                            opts.seq += 1;

                            // 3. update the value on the DHT
                            b.put_mutable(bye, opts);
                        }
                        HyperDhtEvent::PutMutableResult { opts, .. } => {
                            // 4. value updated, signal node `a` that it can try to get it
                            tx.send(()).await.unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });

        loop {
            select! {
                _ = rx.next() => {
                    // 5. get the updated value on the DHT
                    a.get_mutable(key.clone());
                },
                ev = a.next().fuse() => {
                    if let Some(HyperDhtEvent::GetMutableResult(get)) = ev {
                        // 6. received the updated value after querying the DHT
                        assert_eq!(get.len(), num_spawned + 1);
                        let expected_val = Some(bye.to_vec());
                        assert!(get.values().all(|mutable| mutable.value == expected_val));
                        return  Ok(());
                    }
                }
            };
        }
    }

    #[async_std::test]
    async fn immutable_put_get() -> Result<(), Box<dyn std::error::Error>> {
        // create an ephemeral bootstrap node
        let bs_addr = bootstrap_dht!();
        // spawn some nodes bootstrapped with `bs`
        let num_spawned = 10;
        spawn_dhts!(num_spawned, &[bs_addr]);

        let payload = b"hello friend!";

        let mut a =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;
        a.next().await;
        a.put_immutable(payload);
        let key = match a.next().await {
            Some(HyperDhtEvent::PutImmutableResult { key, .. }) => {
                assert_eq!(key, crypto::hash_id(payload));
                key
            }
            _ => panic!("expected result for the immutable value"),
        };
        async_std::task::spawn(async move {
            loop {
                a.next().await;
            }
        });

        let mut b =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;

        // value not yet available locally
        assert!(b.get_immutable(key.clone()).is_left());
        loop {
            if let Some(HyperDhtEvent::GetImmutableResult(get)) = b.next().await {
                assert_eq!(get.key, key);
                // expected answers from every non ephemeral node `num_spawned` + `a`
                assert_eq!(get.len(), num_spawned + 1);
                assert!(get.values().all(|val| val == payload));
                break;
            }
        }

        // value now available locally, no need to query the DHT.
        assert_eq!(
            b.get_immutable(key.clone()),
            Either::Right((key, payload.to_vec()))
        );

        Ok(())
    }

    #[async_std::test]
    async fn local_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
        // ephemeral node used for bootstrapping
        let bs_addr = bootstrap_dht!();

        // represents stateful nodes in the DHT
        let mut state =
            HyperDht::with_config(DhtConfig::default().set_bootstrap_nodes(&[&bs_addr])).await?;

        let (tx, rx) = futures::channel::oneshot::channel();

        async_std::task::spawn(async move {
            if let Some(HyperDhtEvent::Bootstrapped { .. }) = state.next().await {
                // after initial bootstrapping the state`s address is included in the bs` routing table. Then the `node` can start to announce
                tx.send(()).expect("Failed to send");
            } else {
                panic!("expected bootstrap result first")
            }
            loop {
                state.next().await;
            }
        });

        let port = 12345;
        // announce options
        let opts = QueryOpts::new(IdBytes::random()).port(port);

        let mut node = HyperDht::with_config(
            DhtConfig::default()
                .ephemeral()
                .set_bootstrap_nodes(&[bs_addr]),
        )
        .await?;

        // wait until `state` is bootstrapped
        rx.await?;

        let mut unannounced = false;
        loop {
            if let Some(event) = node.next().await {
                match event {
                    HyperDhtEvent::Bootstrapped { .. } => {
                        // 1. announce topic and port
                        node.announce(opts.clone());
                    }
                    HyperDhtEvent::AnnounceResult { .. } => {
                        // 2. look up the announced topic
                        node.lookup(opts.topic.clone());
                    }
                    HyperDhtEvent::LookupResult { lookup, .. } => {
                        if unannounced {
                            // 5. after un announcing lookup yields zero peers
                            assert!(lookup.is_empty());
                            return Ok(());
                        }
                        assert_eq!(lookup.topic, opts.topic);
                        assert_eq!(lookup.len(), 1);
                        let remotes = lookup.remotes().cloned().collect::<Vec<_>>();
                        assert_eq!(remotes.len(), 1);

                        let mut node_addr = node.local_addr()?;
                        if let SocketAddr::V4(mut addr) = node_addr {
                            addr.set_port(port as u16);
                            assert_eq!(remotes[0], SocketAddr::V4(addr));
                        }
                        // 3. un announce the port
                        node.unannounce(opts.clone());
                    }
                    HyperDhtEvent::UnAnnounceResult { .. } => {
                        // 4. another lookup that now comes up empty
                        unannounced = true;
                        node.lookup(opts.topic.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn verify_mutable() {
        let mut opts = PutOpts::with_keypair(crypto::keypair());
        let key = opts.id();
        let a = opts.mutable(b"v1".to_vec());
        assert!(verify(&key, &a).is_ok());
        opts.seq += 1;
        let b = opts.mutable(b"v2".to_vec());
        assert!(verify(&key, &b).is_ok());
    }
}
