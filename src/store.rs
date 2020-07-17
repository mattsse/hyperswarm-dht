use fnv::FnvHashMap;
use lru::LruCache;

use crate::crypto;
use crate::dht_proto::Mutable;
use crate::rpc::message::Type;
use crate::rpc::query::{CommandQuery, QueryId};
use crate::rpc::IdBytes;
use crate::{IMMUTABLE_STORE_CMD, MUTABLE_STORE_CMD};
use prost::Message;
use std::hash::{Hash, Hasher};

enum StorageEntry {
    Mutable(Mutable),
    Immutable(Vec<u8>),
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
    inner: LruCache<StorageKey, Vec<u8>>,
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
    pub fn on_command(&mut self, query: &CommandQuery) -> Result<Option<Vec<u8>>, String> {
        assert_eq!(query.command.as_str(), IMMUTABLE_STORE_CMD);
        if query.ty == Type::Update {
            self.update(query)
        } else {
            self.query(query)
        }
    }

    pub fn on_command_mut(&mut self, query: &CommandQuery) -> Result<Option<Vec<u8>>, String> {
        assert_eq!(query.command.as_str(), MUTABLE_STORE_CMD);

        if let Some(mutable) = query
            .value
            .as_ref()
            .and_then(|buf| Mutable::decode(buf.as_slice()).ok())
        {
            if query.ty == Type::Update {
                self.update_mut(query, mutable)
            } else {
                self.query_mut(query, mutable)
            }
        } else {
            Ok(None)
        }
    }

    pub fn get(&mut self) {}

    pub fn put(&mut self) {}

    fn query_mut(
        &mut self,
        query: &CommandQuery,
        mutable: Mutable,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn update_mut(
        &mut self,
        query: &CommandQuery,
        mutable: Mutable,
    ) -> Result<Option<Vec<u8>>, String> {
        if mutable.value.is_none() || mutable.signature.is_none() {
            return Ok(None);
        }

        let public_key = query.target.clone();

        let key = if let Some(salt) = mutable.salt {
            StorageKey::Mutable(
                public_key
                    .as_ref()
                    .into_iter()
                    .cloned()
                    .chain(salt.into_iter())
                    .collect(),
            )
        } else {
            StorageKey::Mutable(public_key.to_vec())
        };

        // let msg = crypto::signable()

        Ok(None)
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Query`].
    fn query(&mut self, query: &CommandQuery) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .inner
            .get(&StorageKey::Immutable(query.target.clone()))
            .cloned())
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Update`].
    fn update(&mut self, query: &CommandQuery) -> Result<Option<Vec<u8>>, String> {
        if let Some(value) = query.value.as_ref() {
            let key = crypto::hash_id(value.as_slice());
            if key != query.target {
                return Err("ERR_INVALID_INPUT".to_string());
            }
            self.inner.put(StorageKey::Immutable(key), value.clone());
        }
        Ok(None)
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
