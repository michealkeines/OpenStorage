# merkle/ — Merkle Tree for Anti-Entropy

**Layer**: L3.
**Role**: builds and walks a Merkle tree over snapshot pages so vault replicas can reconcile cheaply.

## What lives here

- Tree depth fixed at 15 (32K leaves).
- Leaf = `BLAKE3(page_id || page_version || payload_hash)` for one bucketed snapshot page.
- Build: incremental update on dirty pages; full rebuild rare.
- Compare: given two roots, walk down to find divergent subtree.
- Pull: list the (page_id, page_version) leaves in a divergent range.

## Boundaries

- Depends on `types/`, `entities/` (snapshot page hash).
- Built by `metadata/`'s snapshot path.
- Walked by `antientropy/` during reconciliation.

## Flow

```
   build (incremental):
     for each dirty page:
       leaf_hash = BLAKE3(page_id || page_version || payload_hash)
       update path from leaf to root
   
   compare two trees (local vs. remote replica):
     if root_local == root_remote: done, no divergence
     else:
       walk down depth by depth, comparing subtree hashes
       at the deepest divergent node, list affected leaves
       hand list of (page_id, page_version) to antientropy/
```

## Inputs / Outputs

- Build inputs: dirty page descriptors.
- Compare inputs: two root hashes, then iterative subtree hashes.
- Outputs: list of divergent (page_id, page_version) for the antientropy module to fetch.

## Invariants this module supports

- **I6** — efficient cross-vault reconciliation; bandwidth O(d × log N + |divergent|).
- Correctness: identical metadata → identical root.

## Implementation notes

- Bucket pages into 32K leaves by `hash(page_id) mod 32768`. Many pages may share a leaf bucket; the leaf hash incorporates all members.
- Updates happen on snapshot delta application: dirty leaves recomputed, ancestors rehashed.
- The tree itself fits in ~2 MB (2× 32K × 32 bytes for leaves + interior); compute on-the-fly is OK.
- Root + path is what's actually transmitted between vaults — small (a few KB).

## Tests

- Empty / single-leaf / full-tree all produce stable roots.
- Adding/removing a page changes only the affected path (hash propagation correctness).
- Compare produces exactly the divergent leaves; no false positives in matching subtrees.
- Adversarial: a vault provider returning a wrong root → divergence is found at a deeper level; pull verifies hashes against expected.
