pub enum StoredEntry<TVal> {
    Mutable(TVal),
    Immutable(TVal),
}

pub trait Store {
    type Value;
}

pub struct ImmutableStore {
    // TODO cyclic ref DHT <-> Store
// Store::Value should be a buf only
}

pub struct MutableStore {
    // Store::Value should be a buf + keypair
}
