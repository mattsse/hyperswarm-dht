use std::hash::{Hash, Hasher};

use fnv::FnvHashMap;
use lru::LruCache;
use prost::Message;

use crate::dht_proto::Mutable;
use crate::rpc::message::Type;
use crate::rpc::query::{CommandQuery, CommandQueryResponse, QueryId};
use crate::rpc::{IdBytes, Peer};
use crate::{crypto, ERR_INVALID_INPUT};
use crate::{IMMUTABLE_STORE_CMD, MUTABLE_STORE_CMD};
use ed25519_dalek::PublicKey;

enum StorageEntry {
    Mutable(Mutable),
    Immutable(Vec<u8>),
}

impl StorageEntry {
    fn as_mutable(&self) -> Option<&Mutable> {
        if let StorageEntry::Mutable(m) = self {
            Some(m)
        } else {
            None
        }
    }

    fn as_immutable(&self) -> Option<&Vec<u8>> {
        if let StorageEntry::Immutable(i) = self {
            Some(i)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageKey {
    Mutable(Vec<u8>),
    Immutable(IdBytes),
}

impl Hash for StorageKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            StorageKey::Mutable(id) => {
                b"m".hash(state);
                id.hash(state);
            }
            StorageKey::Immutable(id) => {
                b"i".hash(state);
                id.hash(state);
            }
        }
    }
}

impl Eq for StorageKey {}

pub struct Store {
    /// Value cache
    inner: LruCache<StorageKey, StorageEntry>,
    /// Keep track of all matching values from the DHT.
    streams: FnvHashMap<QueryId, ()>,
}

impl Store {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: LruCache::new(cap),
            streams: Default::default(),
        }
    }

    /// Handle an incoming requests for the registered commands and reply.
    pub fn on_command(&mut self, query: CommandQuery) -> CommandQueryResponse {
        assert_eq!(query.command.as_str(), IMMUTABLE_STORE_CMD);
        if query.ty == Type::Update {
            self.update(query)
        } else {
            self.query(query)
        }
    }

    pub fn on_command_mut(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        assert_eq!(query.command.as_str(), MUTABLE_STORE_CMD);
        if let Some(mutable) = query
            .value
            .take()
            .and_then(|buf| Mutable::decode(buf.as_slice()).ok())
        {
            return if query.ty == Type::Update {
                self.update_mut(query, mutable)
            } else {
                self.query_mut(query, mutable)
            };
        }
        query.into_response_with_error(ERR_INVALID_INPUT)
    }

    pub fn get(&mut self) {
        unimplemented!()
    }

    pub fn put(&mut self) {
        unimplemented!()
    }

    fn get_mut_key(mutable: &Mutable, id: &IdBytes) -> StorageKey {
        if let Some(ref salt) = mutable.salt {
            StorageKey::Mutable(
                id.as_ref()
                    .into_iter()
                    .chain(salt.into_iter())
                    .cloned()
                    .collect(),
            )
        } else {
            StorageKey::Mutable(id.to_vec())
        }
    }

    fn query_mut(&mut self, mut query: CommandQuery, mutable: Mutable) -> CommandQueryResponse {
        let key = Self::get_mut_key(&mutable, &query.target);
        if let Some(val) = self.inner.get(&key).and_then(StorageEntry::as_mutable) {
            if val.seq.unwrap_or_default() >= mutable.seq.unwrap_or_default() {
                let mut buf = Vec::with_capacity(val.encoded_len());
                val.encode(&mut buf).unwrap();
                query.value = Some(buf);
            }
        }
        query.into()
    }

    fn update_mut(&mut self, query: CommandQuery, mutable: Mutable) -> CommandQueryResponse {
        if mutable.value.is_none() || mutable.signature.is_none() {
            return query.into();
        }

        let key = Self::get_mut_key(&mutable, &query.target);

        if let Err(err) = verify(&query.target, &mutable) {
            return query.into_response_with_error(err);
        }

        if let Some(local) = self.inner.get(&key).and_then(StorageEntry::as_mutable) {
            if let Err(err) = maybe_seq_error(&mutable, local) {
                let mut resp = query.into_response_with_error(err);
                let mut buf = Vec::with_capacity(local.encoded_len());
                local.encode(&mut buf).unwrap();
                resp.msg.value = Some(buf);
                return resp;
            }
        }

        self.inner.put(key, StorageEntry::Mutable(mutable));
        query.into()
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Query`].
    fn query(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        let val = self
            .inner
            .get(&StorageKey::Immutable(query.target.clone()))
            .and_then(StorageEntry::as_immutable)
            .cloned();
        query.value = val;
        query.into()
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Update`].
    fn update(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        if let Some(value) = query.value.take() {
            let key = crypto::hash_id(value.as_slice());
            if key != query.target {
                return query.into_response_with_error(ERR_INVALID_INPUT);
            }
            self.inner.put(
                StorageKey::Immutable(key),
                StorageEntry::Immutable(value.clone()),
            );
        }
        query.into()
    }
}

#[inline]
fn verify(pk: &IdBytes, mutable: &Mutable) -> Result<(), String> {
    let public_key =
        PublicKey::from_bytes(pk.as_ref()).map_err(|_| ERR_INVALID_INPUT.to_string())?;
    let sig = crypto::signature(&mutable).ok_or_else(|| ERR_INVALID_INPUT.to_string())?;
    let msg = crypto::signable(&mutable).map_err(|_| ERR_INVALID_INPUT.to_string())?;

    crypto::verify(&public_key, &msg, &sig).map_err(|_| ERR_INVALID_INPUT.to_string())
}

#[inline]
fn maybe_seq_error(a: &Mutable, b: &Mutable) -> Result<(), String> {
    let seq_a = a.seq.unwrap_or_default();
    let seq_b = b.seq.unwrap_or_default();
    if a.value.is_some() {
        if seq_a == seq_b && a.value != b.value {
            return Err("ERR_INVALID_SEQ".to_string());
        }
    }
    if seq_a <= seq_b {
        Err("ERR_SEQ_MUST_EXCEED_CURRENT".to_string())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ValueStream {}

pub struct Value {
    value: Vec<u8>,
    salt: Option<Vec<u8>>,
    signature: Vec<u8>,
    seq: u64,
}
