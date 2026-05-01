//! os-antientropy — Merkle reconcile across vault providers.
//!
//! Skeleton: provides the divergence-walk primitive on top of `os-merkle`.
//! Full reconcile (page pull, snapshot apply) lands when the snapshot path
//! is wired.

#![forbid(unsafe_code)]

use os_merkle::MerkleTree;
use os_types::BlakeHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AntiEntropyError {
    #[error("tree size mismatch: local {local}, remote {remote}")]
    SizeMismatch { local: usize, remote: usize },
}

#[derive(Debug, Clone)]
pub struct DivergenceReport {
    pub local_root: BlakeHash,
    pub remote_root: BlakeHash,
    pub divergent_leaf_indices: Vec<usize>,
}

pub fn compare(
    local: &MerkleTree,
    remote_leaves: &[BlakeHash],
) -> Result<DivergenceReport, AntiEntropyError> {
    if remote_leaves.len() != local.leaves().len() {
        return Err(AntiEntropyError::SizeMismatch {
            local: local.leaves().len(),
            remote: remote_leaves.len(),
        });
    }
    let local_root = local.root();
    let mut remote_tree = MerkleTree::new();
    // We can't reconstruct the full remote tree without its members; the
    // caller computes the remote root themselves and passes leaves. We
    // approximate the remote root by hashing levels up from the leaves.
    let remote_root = remote_root_from_leaves(remote_leaves);
    let _ = remote_tree;
    let divergent_leaf_indices = local.divergent_leaves(remote_leaves);
    Ok(DivergenceReport {
        local_root,
        remote_root,
        divergent_leaf_indices,
    })
}

fn remote_root_from_leaves(leaves: &[BlakeHash]) -> BlakeHash {
    let mut level: Vec<BlakeHash> = leaves.to_vec();
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
    *level.first().unwrap_or(&BlakeHash::from_bytes([0u8; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_trees_have_no_divergence() {
        let a = MerkleTree::new();
        let b_leaves = a.leaves().to_vec();
        let r = compare(&a, &b_leaves).unwrap();
        assert!(r.divergent_leaf_indices.is_empty());
        assert_eq!(r.local_root, r.remote_root);
    }
}
