use crate::kbucket::KeyBytes;
use crate::rpc::PeerId;

pub struct QueryTable {
    k: u64,
    id: KeyBytes,
    target: KeyBytes,
    closest: Vec<PeerId>,
    unverified: Vec<PeerId>,
}

impl QueryTable {
    pub fn new(id: KeyBytes, target: KeyBytes) -> Self {
        Self {
            k: 20,
            id,
            target,
            closest: vec![],
            unverified: vec![],
        }
    }

    fn reset_queried(&mut self) {}
}
