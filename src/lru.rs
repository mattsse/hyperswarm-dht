use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::Duration;

use fnv::FnvHashMap;
use smallvec::alloc::collections::VecDeque;
use wasm_timer::Instant;

use crate::rpc::IdBytes;

#[derive(Debug, Clone)]
pub enum Address {
    Remote(SocketAddr),
    Local([u8; 4]),
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Remote(addr)
    }
}

impl From<[u8; 4]> for Address {
    fn from(addr: [u8; 4]) -> Self {
        Address::Local(addr)
    }
}

#[derive(Debug, Clone, Hash, PartialOrd, PartialEq, Eq)]
pub enum CacheKey {
    Local { id: IdBytes, prefix: [u8; 2] },
    Remote(IdBytes),
}

impl CacheKey {
    pub fn id(&self) -> &IdBytes {
        match self {
            CacheKey::Local { id, .. } => id,
            CacheKey::Remote(id) => id,
        }
    }

    pub fn into_id(self) -> IdBytes {
        match self {
            CacheKey::Local { id, .. } => id,
            CacheKey::Remote(id) => id,
        }
    }
}

impl Ord for CacheKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if let CacheKey::Local {
            id: id1,
            prefix: r1,
        } = self
        {
            if let CacheKey::Local {
                id: id2,
                prefix: r2,
            } = other
            {
                return id1.0.cmp(&id2.0).then(r1.cmp(&r2));
            }
        }
        self.id().0.cmp(&other.id().0)
    }
}

#[derive(Debug)]
pub enum AddressCache {
    Remote(CacheEntry<SocketAddr>),
    Local(CacheEntry<[u8; 4]>),
}

impl AddressCache {
    fn new(addr: Address, expiration: Instant) -> Self {
        match addr {
            Address::Remote(addr) => AddressCache::Remote(CacheEntry::new(addr, expiration)),
            Address::Local(addr) => AddressCache::Local(CacheEntry::new(addr, expiration)),
        }
    }

    /// Whether this entry and all addresses are expired.
    fn is_expired(&self, now: Instant) -> bool {
        match self {
            AddressCache::Remote(c) => c.is_expired(now),
            AddressCache::Local(c) => c.is_expired(now),
        }
    }

    fn insert(&mut self, addr: Address, expiration: Instant) -> bool {
        match addr {
            Address::Remote(addr) => {
                if let AddressCache::Remote(entry) = self {
                    entry.expiration = expiration;
                    let present = entry.inner.contains_key(&addr);
                    if present {
                        PeerCache::update_key(&mut entry.list, &addr);
                    } else {
                        entry.list.push_back(addr);
                    };
                    entry.inner.insert(addr, expiration);
                    return !present;
                }
            }
            Address::Local(addr) => {
                if let AddressCache::Local(entry) = self {
                    entry.expiration = expiration;
                    let present = entry.inner.contains_key(&addr);
                    if present {
                        PeerCache::update_key(&mut entry.list, &addr);
                    } else {
                        entry.list.push_back(addr);
                    };
                    entry.inner.insert(addr, expiration);
                    return !present;
                }
            }
        }
        false
    }

    /// Removes least recently used address.
    fn remove_lru(&mut self) -> bool {
        match self {
            AddressCache::Remote(c) => c.remove_lru().is_some(),
            AddressCache::Local(c) => c.remove_lru().is_some(),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            AddressCache::Remote(c) => c.is_empty(),
            AddressCache::Local(c) => c.is_empty(),
        }
    }

    fn set_expiration(&mut self, expiration: Instant) {
        match self {
            AddressCache::Remote(c) => {
                c.expiration = expiration;
            }
            AddressCache::Local(c) => {
                c.expiration = expiration;
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            AddressCache::Remote(c) => c.len(),
            AddressCache::Local(c) => c.len(),
        }
    }

    fn remove_expired(&mut self, now: Instant) -> usize {
        match self {
            AddressCache::Remote(c) => c.remove_expired(now).len(),
            AddressCache::Local(c) => c.remove_expired(now).len(),
        }
    }

    pub fn iter_locals<'a>(&'a self) -> Option<impl Iterator<Item = &[u8; 4]> + 'a> {
        if let AddressCache::Local(cache) = self {
            Some(cache.list.iter())
        } else {
            None
        }
    }

    pub fn iter_remotes<'a>(&'a self) -> Option<impl Iterator<Item = &SocketAddr> + 'a> {
        if let AddressCache::Remote(cache) = self {
            Some(cache.list.iter())
        } else {
            None
        }
    }

    pub fn remotes(&self) -> Option<&VecDeque<SocketAddr>> {
        if let AddressCache::Remote(cache) = self {
            Some(&cache.list)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct CacheEntry<T> {
    inner: FnvHashMap<T, Instant>,
    list: VecDeque<T>,
    expiration: Instant,
}

impl<T: Hash + Eq + Copy> CacheEntry<T> {
    fn new(val: T, expiration: Instant) -> Self {
        let mut inner = FnvHashMap::default();
        inner.insert(val, expiration);
        let mut list = VecDeque::default();
        list.push_back(val);
        Self {
            inner,
            list,
            expiration,
        }
    }
}

impl<T: Hash + Eq> CacheEntry<T> {
    /// Whether this entry and all addresses are expired.
    fn is_expired(&self, now: Instant) -> bool {
        now > self.expiration
    }

    fn remove_expired(&mut self, now: Instant) -> Vec<T> {
        let mut expired_values = vec![];
        for key in self.list.iter() {
            if self.inner[key] >= now {
                break;
            }
            if let Some((addr, _)) = self.inner.remove_entry(key) {
                expired_values.push(addr);
            }
        }
        // remove keys
        let _ = self.list.drain(..expired_values.len());

        expired_values
    }

    /// Removes least recently used address.
    fn remove_lru(&mut self) -> Option<T> {
        if let Some(key) = self.list.pop_front() {
            self.inner.remove(&key);
            Some(key)
        } else {
            None
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Implementation of a LRU Cache with expiration
pub struct PeerCache {
    /// Cache that stores the peers and their expiration timestamps
    map: FnvHashMap<CacheKey, AddressCache>,
    /// list to keep track of lru keys
    list: VecDeque<CacheKey>,
    /// maximum allowed capacity of this cache
    capacity: usize,
    /// currently stored addresses
    cnt: usize,
    /// How long an entry is valid
    age: Duration,
}

impl PeerCache {
    pub fn new(capacity: usize, age: Duration) -> Self {
        Self {
            map: Default::default(),
            list: Default::default(),
            capacity,
            cnt: 0,
            age,
        }
    }

    fn remove_expired(&mut self, now: Instant) {
        let (map, list) = (&mut self.map, &mut self.list);

        let mut expired_keys = 0;
        for key in list.iter() {
            let addrs = map.get_mut(key).unwrap();

            if !addrs.is_expired(now) {
                self.cnt -= addrs.remove_expired(now);
                if addrs.is_empty() {
                    map.remove(key);
                    expired_keys += 1;
                }
                break;
            }
            // all addresses expired
            if let Some(addrs) = map.remove(key) {
                expired_keys += 1;
                self.cnt -= addrs.len();
            }
        }
        // remove keys as well
        list.drain(..expired_keys);
    }

    // Move `key` in the ordered list to the last
    fn update_key<Key, Q: ?Sized>(list: &mut VecDeque<Key>, key: &Q)
    where
        Key: Borrow<Q>,
        Q: Ord,
    {
        if let Some(pos) = list.iter().position(|k| k.borrow() == key) {
            let _ = list.remove(pos).map(|it| list.push_back(it));
        }
    }

    /// Clears the `PeerCache`, removing all values.
    pub fn clear(&mut self) {
        self.map.clear();
        self.list.clear();
        self.cnt = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.cnt == 0
    }

    pub fn len(&self) -> usize {
        self.cnt
    }

    /// Removes least recently used items to make space for new ones.
    fn remove_lru(&mut self, now: Instant) {
        while self.cnt >= self.capacity {
            let mut empty_addrs = false;
            if let Some(key) = self.list.iter().next() {
                let addrs = self.map.get_mut(key).unwrap();
                if addrs.remove_lru() {
                    self.cnt -= 1;
                } else {
                    empty_addrs = self.map.remove_entry(key).is_some();
                    assert!(empty_addrs);
                }
            }
            if empty_addrs {
                self.list.pop_front();
            }
        }
    }

    pub fn insert(&mut self, key: CacheKey, addr: impl Into<Address>) {
        let addr = addr.into();
        let now = Instant::now();
        self.remove_expired(now);
        if let Some(addrs) = self.map.get_mut(&key) {
            Self::update_key(&mut self.list, &key);
            if addrs.insert(addr, now + self.age) {
                self.cnt += 1;
            }
        } else {
            self.remove_lru(now);
            self.list.push_back(key.clone());
            self.map
                .insert(key, AddressCache::new(addr, now + self.age));
            self.cnt += 1;
        }
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<&mut AddressCache> {
        let now = Instant::now();
        self.remove_expired(now);

        let expiration = now + self.age;
        let list = &mut self.list;
        self.map.get_mut(key).map(|addrs| {
            Self::update_key(list, key);
            addrs.set_expiration(expiration);
            addrs
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;

    fn sleep(time: u64) {
        use std::thread;
        thread::sleep(Duration::from_millis(time));
    }

    #[test]
    fn expiration() {
        let ttl = Duration::from_millis(50);
        let mut lru_cache = PeerCache::new(10, ttl);

        assert_eq!(lru_cache.len(), 0);

        let key = CacheKey::Remote(IdBytes::random());
        let addr = Address::Remote("127.0.0.1:0".parse().unwrap());

        lru_cache.insert(key.clone(), addr.clone());
        assert_eq!(lru_cache.len(), 1);

        sleep(51);

        assert!(lru_cache.get(&key).is_none());
        assert_eq!(lru_cache.len(), 0);
    }

    #[test]
    fn capacity() {
        let ttl = Duration::from_millis(100);
        let size = 10;
        let mut lru_cache = PeerCache::new(size, ttl);

        for i in 0..1000 {
            if i < size {
                assert_eq!(lru_cache.len(), i);
            }

            let key = CacheKey::Remote(IdBytes::random());
            let addr = Address::Remote("127.0.0.1:0".parse().unwrap());

            let _ = lru_cache.insert(key, addr);

            if i < size {
                assert_eq!(lru_cache.len(), i + 1);
            } else {
                assert_eq!(lru_cache.len(), size);
            }
        }

        sleep(101);
        let key = CacheKey::Remote(IdBytes::random());
        let addr = Address::Remote("127.0.0.1:0".parse().unwrap());
        lru_cache.insert(key, addr);

        assert_eq!(lru_cache.len(), 1);
    }
}
