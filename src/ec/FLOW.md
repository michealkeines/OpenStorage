# ec/ — Erasure Coding

**Layer**: L3.
**Role**: Reed–Solomon encode and reconstruct. Pure computation; no I/O, no state.

## What lives here

- `encode(ciphertext, k, n)` → list of `n` shards, each carrying `shard_index ∈ 0..n`.
- `reconstruct(any K healthy shards)` → ciphertext, or error if fewer than K available.
- Galois-field arithmetic primitives; CPU-feature-detected fast paths (AVX2/SSSE3/NEON).

## Boundaries

- Depends on `types/` only.
- Pure: same inputs → same outputs. No randomness. No I/O.
- Called by `chunk/` on write and read paths.

## Flow

```
                   write path                                    read path
                   ──────────                                    ─────────
                   ciphertext                              K of N shards
                       │                                          │
                       ▼                                          ▼
                ┌────────────┐                              ┌────────────┐
                │  encode    │                              │ reconstruct│
                │  (RS k,n)  │                              │   (RS k,n) │
                └─────┬──────┘                              └──────┬─────┘
                      │                                            │
                      ▼                                            ▼
                  N shards                                    ciphertext
              (with shard_index)                          (or InsufficientShards)
```

## Inputs / Outputs

- Inputs: ciphertext bytes; (k, n) parameters from `Chunk.ec_scheme`.
- Outputs: shards as fixed-size byte arrays; `shard_index` recorded per shard.

## Invariants this module preserves

- **I3 (availability)** — given K healthy shards out of N, reconstruction always succeeds.
- **I2 (integrity)** — does NOT verify content; that's the AEAD layer's job. EC is pure coding theory.

## Implementation notes

- Use a vetted Reed–Solomon library; do not roll our own GF math. (`reed-solomon-erasure` or similar.)
- `Chunk.ec_scheme` may vary across chunks (per [`../placement/FLOW.md`](../placement/FLOW.md) dynamic EC selection); both encode and reconstruct take `(k, n)` as parameters per call.
- Shard size = ⌈ciphertext_size / k⌉; the last shard may be padded.
- Replication mode (factor R) is implemented as the degenerate EC scheme `(k=1, n=R)`. Same code path; no special-case logic.

## Tests

- Round-trip: `reconstruct(any K of encode(x, k, n)) == x` for all valid (k, n) and all K-subsets.
- Performance benchmark: encode + reconstruct stay within budget for typical 4 MB ciphertext.
- Adversarial: corrupt shard bytes → reconstruct produces *some* output but AEAD layer (above) catches the mismatch. EC alone cannot detect corruption.
