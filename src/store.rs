use fnv::FnvHashMap;
use lru::LruCache;

use crate::rpc::query::QueryId;

pub enum StoredEntry<TVal> {
    Mutable(TVal),
    Immutable(TVal),
}

pub struct ImmutableStore {
    // TODO cyclic ref DHT <-> Store
// Store::Value should be a buf only
}

pub struct MutableStore {
    // Store::Value should be a buf + keypair
}

pub struct Store<T> {
    /// Value cache
    inner: LruCache<String, T>,
    /// Keep track of all matching values from the DHT.
    streams: FnvHashMap<QueryId, ()>,
}

#[derive(Debug)]
pub struct ValueStream {}

pub struct Value {
    value: Vec<u8>,
    salt: Option<Vec<u8>>,
    signature: Vec<u8>,
    seq: u64,
}
