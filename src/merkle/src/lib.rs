//! os-merkle — fixed-depth Merkle tree (depth 15, 32K leaves) for anti-entropy.
//!
//! Pages bucket into leaves by `hash(page_id) % 32768`. Each leaf hash is the
//! BLAKE3 hash of the concatenation of `(page_id || page_version || payload_hash)`
//! tuples for all pages bucketed there. Interior nodes are
//! `BLAKE3(left || right)`.

#![forbid(unsafe_code)]

use os_types::BlakeHash;

pub const DEPTH: u32 = 15;
pub const LEAVES: usize = 1 << DEPTH; // 32_768

pub struct MerkleTree {
    /// Per-leaf hash. Index = bucket id.
    leaves: Vec<BlakeHash>,
    /// Per-leaf bucket members `(page_id, page_version, payload_hash)`. Used
    /// for incremental updates.
    leaf_members: Vec<Vec<LeafMember>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafMember {
    pub page_id: Vec<u8>,
    pub page_version: u64,
    pub payload_hash: BlakeHash,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: vec![BlakeHash::from_bytes([0u8; 32]); LEAVES],
            leaf_members: vec![Vec::new(); LEAVES],
        }
    }

    pub fn upsert(&mut self, m: LeafMember) {
        let bucket = bucket_for(&m.page_id);
        let members = &mut self.leaf_members[bucket];
        match members.iter().position(|x| x.page_id == m.page_id) {
            Some(i) => members[i] = m,
            None => members.push(m),
        }
        members.sort_by(|a, b| a.page_id.cmp(&b.page_id));
        self.leaves[bucket] = leaf_hash(members);
    }

    pub fn remove(&mut self, page_id: &[u8]) {
        let bucket = bucket_for(page_id);
        let members = &mut self.leaf_members[bucket];
        members.retain(|m| m.page_id != page_id);
        self.leaves[bucket] = leaf_hash(members);
    }

    pub fn root(&self) -> BlakeHash {
        let mut level: Vec<BlakeHash> = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let l = pair[0];
                let r = if pair.len() == 2 { pair[1] } else { pair[0] };
                let mut hasher = blake3::Hasher::new();
                hasher.update(l.as_bytes());
                hasher.update(r.as_bytes());
                next.push(BlakeHash::from_bytes(*hasher.finalize().as_bytes()));
            }
            level = next;
        }
        level[0]
    }

    /// Find divergent leaf indices vs. another tree's leaves. Caller has the
    /// remote leaf bytes (e.g., fetched layer-by-layer).
    pub fn divergent_leaves(&self, remote_leaves: &[BlakeHash]) -> Vec<usize> {
        self.leaves
            .iter()
            .zip(remote_leaves.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn leaves(&self) -> &[BlakeHash] {
        &self.leaves
    }

    pub fn leaf_members(&self, bucket: usize) -> &[LeafMember] {
        &self.leaf_members[bucket]
    }
}

fn bucket_for(page_id: &[u8]) -> usize {
    let h = blake3::hash(page_id);
    let bytes = h.as_bytes();
    let mut idx = [0u8; 4];
    idx.copy_from_slice(&bytes[..4]);
    (u32::from_le_bytes(idx) as usize) & (LEAVES - 1)
}

fn leaf_hash(members: &[LeafMember]) -> BlakeHash {
    if members.is_empty() {
        return BlakeHash::from_bytes([0u8; 32]);
    }
    let mut hasher = blake3::Hasher::new();
    for m in members {
        hasher.update(&(m.page_id.len() as u32).to_be_bytes());
        hasher.update(&m.page_id);
        hasher.update(&m.page_version.to_be_bytes());
        hasher.update(m.payload_hash.as_bytes());
    }
    BlakeHash::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ph(b: u8) -> BlakeHash {
        BlakeHash::from_bytes([b; 32])
    }

    #[test]
    fn empty_tree_root_stable() {
        let a = MerkleTree::new();
        let b = MerkleTree::new();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn root_changes_after_upsert() {
        let mut a = MerkleTree::new();
        let r0 = a.root();
        a.upsert(LeafMember {
            page_id: b"page-1".to_vec(),
            page_version: 1,
            payload_hash: ph(7),
        });
        assert_ne!(a.root(), r0);
    }

    #[test]
    fn divergent_leaves_found() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        a.upsert(LeafMember {
            page_id: b"p-1".to_vec(),
            page_version: 1,
            payload_hash: ph(1),
        });
        b.upsert(LeafMember {
            page_id: b"p-1".to_vec(),
            page_version: 2,
            payload_hash: ph(2),
        });
        let div = a.divergent_leaves(b.leaves());
        assert_eq!(div.len(), 1);
        assert_eq!(div[0], bucket_for(b"p-1"));
    }

    #[test]
    fn upsert_idempotent_for_same_member() {
        let mut a = MerkleTree::new();
        a.upsert(LeafMember {
            page_id: b"p".to_vec(),
            page_version: 1,
            payload_hash: ph(1),
        });
        let r1 = a.root();
        a.upsert(LeafMember {
            page_id: b"p".to_vec(),
            page_version: 1,
            payload_hash: ph(1),
        });
        assert_eq!(a.root(), r1);
    }
}
