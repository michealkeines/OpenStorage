# bloom/ — Per-Vault Bloom Filter

**Layer**: L3.
**Role**: probabilistic existence check over the chunk-hash set. Used for fast dedup probes, pre-write existence checks, and scrub planning.

## What lives here

- Bloom filter sized for `bloom.expected_chunks` at `bloom.target_fpr` (default 50M chunks at 1% FPR ≈ 60 MB).
- Add / contains / approximate-size operations.
- Salted hash functions (salt derived from MK under `kp:bloom-salt`) so the filter doesn't leak chunk-hash values to anyone observing the on-disk bytes.
- Persistence: rebuilt cheaply from chunk records during snapshot compaction.

## Boundaries

- Depends on `types/`, `crypto/` (for the salt derivation).
- Read by `chunk/` (dedup checks) and `repair/` (existence verification).
- Written by `metadata/` during compaction.

## Flow

```
   on chunk write:
     chunk_hash ──► bloom.add()
                          │
                          ▼
                    in-memory bitfield

   on potential dedup:
     candidate_hash ──► bloom.contains() ?
                              │
                              ├── definitely not  → no dedup possible; proceed with new chunk
                              └── probably yes    → metadata/ lookup to confirm

   on snapshot compaction:
     metadata/ enumerate chunk records ──► fresh bloom filter ──► persist alongside snapshot
```

## Inputs / Outputs

- Inputs: chunk hashes from `chunk/`.
- Outputs: `Yes (probably)` / `No (definitely)` queries.
- Side: emits `bloom.fpr_warning` if estimated FPR climbs past target between rebuilds.

## Invariants this module supports

- Correctness invariant: `contains(h) == false` ⇒ `h` was never added (no false negatives).
- Privacy: stored bitfield reveals nothing about chunk hashes (salted).

## Implementation notes

- Standard double-hashing trick (k=7 hashes from 2 base hashes) for speed.
- Rebuild on compaction is O(num chunks) memory walk; cheap relative to snapshot.
- The salt makes the filter unique per vault; two vaults with overlapping content have unrelated bitfields.
- Don't use the FPR as a security boundary. False positives are acceptable; just trigger a metadata lookup.

## Tests

- No false negatives across millions of inserts.
- FPR matches theoretical at design fill level (within tolerance).
- Rebuild idempotency: rebuilding from same chunk set produces identical filter.
- Salt change → completely different filter for same chunks.
