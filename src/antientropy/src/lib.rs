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
    #[error("forged page at leaf {index}: hash mismatch")]
    ForgedPage { index: usize },
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

/// F-HM-3 — pull divergent pages from a remote replica and apply them.
///
/// `pages` is a `(leaf_index → page_bytes)` mapping the caller fetched
/// from the remote replica for the indices identified by `compare()`. The
/// hash check is the integrity guarantee: forged pages don't satisfy the
/// remote leaf hash and are rejected (per spec edge case "Replica
/// returning forged Merkle root: page-level hash check during pull
/// catches the fraud").
///
/// Apply is delegated via the supplied `apply_page` closure — the caller
/// owns the metadata mutation; this module owns the divergence walk and
/// integrity check.
pub fn apply_divergent_pages<F>(
    report: &DivergenceReport,
    remote_leaves: &[BlakeHash],
    pages: &[(usize, Vec<u8>)],
    mut apply_page: F,
) -> Result<usize, AntiEntropyError>
where
    F: FnMut(usize, &[u8]),
{
    let mut applied = 0usize;
    for (idx, bytes) in pages {
        // Page must hash to the remote leaf hash for that index.
        let want = remote_leaves
            .get(*idx)
            .ok_or(AntiEntropyError::SizeMismatch {
                local: remote_leaves.len(),
                remote: *idx,
            })?;
        let got = BlakeHash::from_bytes(*blake3::hash(bytes).as_bytes());
        if &got != want {
            return Err(AntiEntropyError::ForgedPage { index: *idx });
        }
        if !report.divergent_leaf_indices.contains(idx) {
            // Caller asked us to apply a page for an index we never marked
            // as divergent — almost certainly a bug; ignore it rather than
            // silently overwriting the local copy.
            continue;
        }
        apply_page(*idx, bytes);
        applied += 1;
    }
    Ok(applied)
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

    /// F-HM-3 — divergent pages are applied iff their hash matches the
    /// remote leaf. Forged pages raise `ForgedPage`. Builds a synthetic
    /// `DivergenceReport` so this test stays decoupled from the real
    /// 32K-leaf Merkle layout.
    #[test]
    fn divergent_page_application_with_hash_check() {
        let remote_page = b"remote-page-bytes";
        let remote_leaf = BlakeHash::from_bytes(*blake3::hash(remote_page).as_bytes());
        // Two synthetic leaves; only leaf index 1 differs.
        let remote_leaves = vec![BlakeHash::from_bytes([1u8; 32]), remote_leaf];
        let report = DivergenceReport {
            local_root: BlakeHash::from_bytes([0u8; 32]),
            remote_root: BlakeHash::from_bytes([0u8; 32]),
            divergent_leaf_indices: vec![1],
        };

        let mut applied: Vec<(usize, Vec<u8>)> = Vec::new();
        let n = apply_divergent_pages(
            &report,
            &remote_leaves,
            &[(1, remote_page.to_vec())],
            |idx, bytes| applied.push((idx, bytes.to_vec())),
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(applied, vec![(1, remote_page.to_vec())]);

        // A forged page (claims to be at leaf 1 but doesn't hash to its
        // leaf) is rejected.
        let err = apply_divergent_pages(
            &report,
            &remote_leaves,
            &[(1, b"forged-content".to_vec())],
            |_, _| {},
        );
        assert!(matches!(err, Err(AntiEntropyError::ForgedPage { .. })));
    }
}
