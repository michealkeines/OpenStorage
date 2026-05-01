# chunk/ — Chunk Engine (Pure Transform)

**Layer**: L3.
**Role**: implements `ChunkEngineContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.3). **Pure transform** — split / hash / encrypt / EC-encode on writes; EC-reconstruct / decrypt on reads. **No orchestration**: does not call placement, does not call plugin_host, does not call wal or metadata. The caller (vfs/, repair/) drives the orchestration; chunk/ supplies primitives.

## What lives here

- Chunking strategy: fixed-size (default 4 MB) and content-defined (FastCDC, opt-in).
- Hashing: BLAKE3 over `vault_salt || plaintext` by default; over `plaintext` only in legacy mode.
- Encrypt-then-EC: chunk plaintext → AEAD ciphertext → EC-encoded shards (returned as a list).
- Reassembly: K healthy shard ciphertexts → ciphertext (via `ec/`) → AEAD verify+decrypt → plaintext.
- Tiny-file inline path: for files ≤ `inline.threshold_bytes`, encrypts payload as one AEAD blob (returned as `InlineBlob`).
- CDC attack mitigations (compression + padding + packing) when CDC enabled.

## What does NOT live here (moved to vfs/)

- Hedged-read scheduling (selecting K + H shards, racing fetches, cancelling stragglers).
- Placement decisions.
- Plugin invocation.
- Quorum write coordination.
- WAL / metadata mutations.

These belong to `vfs/` (or `repair/` for repair flows). chunk/ is invoked as a pure function with inputs and returns outputs; the caller fans out the resulting shards to plugins.

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (L2; same-layer composition allowed for primitives), `ec/` (L3 peer).
- Does NOT depend on `placement/`, `plugin_host/`, `wal/`, `metadata/`.
- Called by `vfs/` (write path: split + encrypt; read path: ec_reconstruct + decrypt) and `repair/` (re-place: ec_reconstruct then re-encrypt for new shard placement).

## Flow — Write Path (per chunk)

```
            plaintext stream
                  │
                  ▼
     ┌─────────────────────────┐
     │ split (fixed or FastCDC)│ — emits chunks (chunk_hash, plaintext)
     └─────────────────────────┘
                  │
                  ▼
        for each chunk: chunk/.encrypt_and_encode(...)
          ┌──────────────────────────────────────┐
          │ hash(plaintext, vault_salt)          │── ChunkHash
          │ derive_chunk_key(file_key, idx)      │── ChunkKey
          │ AEAD.encrypt(plaintext, key, nonce,  │
          │              AAD = chunk_hash || idx)│── ciphertext + tag
          │ ec_encode(ciphertext, ec_scheme)     │── list of N shards
          └──────────────────────────────────────┘
                            │
                            ▼
              return shards to caller (vfs/) — vfs/ orchestrates
              placement, plugin invocation, quorum-wait
```

## Flow — Read Path (caller-driven)

```
   caller (vfs/) supplies K healthy shard ciphertexts (it picked them
   via placement/, fetched them via plugin_host/, and may have hedged)
            │
            ▼
   chunk/.reassemble_and_decrypt(K shards, ec_scheme, key, AAD)
            │
            ▼
   ec_reconstruct(K shards) → ciphertext
            │
            ▼
   AEAD.verify + decrypt
     - if any tag fails: return AuthFailure; caller decides to enqueue repair
            │
            ▼
   plaintext returned to caller
```

## Flow — Inline Path (tiny files)

```
   chunk/.pack_inline(plaintext, file_key):
     derive file_key → chunk_key
     AEAD.encrypt(plaintext, key, nonce, AAD=file_id) → blob+tag
     return InlineBlob {blob, nonce, tag}
   (vfs/ writes it into File.inline_payload)
```

## Inputs

- Plaintext byte streams (from `vfs/`).
- File context: `file_id`, `file_key`, vault salt, configured chunking strategy, EC scheme.

## Outputs

- For writes: list of (ChunkHash, list of shard ciphertexts) — caller persists records.
- For reads: plaintext bytes — or AuthFailure if verify fails.
- For inline: InlineBlob — caller persists.

## Invariants this module preserves

- **I1** — Encryption happens *here*, before any caller passes ciphertext to plugin_host.
- **I2** — AEAD verify on every read; any tampered shard surfaces as AuthFailure to the caller.

## Implementation notes

- Pure-transform discipline: no module state, no I/O, no time, no randomness except for AEAD nonces.
- CDC mode includes compression+padding+packing automatically (CDC attack mitigation).
- Inline path is a hard cutoff at write time; growth past threshold is detected by `vfs/`, which converts inline → chunked atomically (emits `file.inline_promoted`).
- For range reads, the caller (vfs/) decides whether to fetch whole shards or sub-ranges; chunk/.reassemble_and_decrypt accepts a range parameter.

## Tests

- Round-trip: stream → split → encrypt → ec_encode → ec_reconstruct → decrypt → verify equals input.
- Chunking determinism: same input + same vault salt → same chunk hashes.
- Inline path: file at threshold-1 bytes → inline; threshold+1 → chunked.
- AuthFailure: corrupt one shard's ciphertext → ec_reconstruct produces bytes, AEAD.verify fails, AuthFailure returned to caller.
- CDC mitigations: with CDC enabled, plaintext-pattern attacks (Truong 2024) infeasible against produced ciphertext.
