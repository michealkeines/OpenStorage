# crypto/ — Cryptographic Primitives

**Layer**: L2 (revised — was L3 in earlier drafts).
**Role**: implements `CryptoContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.2). Owns all cryptographic operations and the in-memory master key.

> **Why L2, not L3**: dependency depth. crypto/ depends only on `types/` (L1) and `keystore/` (L2). Its L3 placement was conceptual ("primitive") but allowed the wal/L2→crypto/L3 layer violation. Crypto is genuinely a primitive byte-operation set, dependency-equivalent to `keystore/`. L2 placement makes the layer rule consistent.

## What lives here

- AEAD encrypt/decrypt (ChaCha20-Poly1305 default; AES-256-GCM auto-selected when AES-NI / ARMv8 crypto extensions present).
- KDF (Argon2id with profile-driven parameters).
- HKDF for sub-key derivation (per `KeyPurpose` enum from `types/`).
- Ed25519 sign/verify.
- ML-KEM-768 encapsulate/decapsulate.
- Master-key zeroization (`crypto-shred`).
- Per-vault salt derivation under `kp:vault-salt`.

## Boundaries

- Depends on `types/` (key purposes, nonces, tags, sigs).
- Talks to `keystore/` (L2) for at-rest master key wrapping; never reads OS secure storage directly.
- **No I/O of any other kind.** No network, no filesystem outside keystore.

## Flow

```
                  ┌─────────────────────────────────────────┐
                  │ crypto/                                 │
                  │                                         │
                  │  derive_master_key(passphrase, params)  │
                  │  derive_subkey(MK, KeyPurpose)          │
                  │  derive_chunk_key(file_key, chunk_idx)  │
                  │  encrypt(plain, key, nonce, aad) → CT,T │
                  │  decrypt(CT, key, nonce, aad, T)        │
                  │  sign / verify (Ed25519)                │
                  │  kem_encapsulate / decapsulate (ML-KEM) │
                  │  zeroize(MK)  ← crypto-shred            │
                  └─────────────────┬───────────────────────┘
                                    │ called by
        ┌────────┬─────────┬────────┼─────────┬────────┬──────────┐
        ▼        ▼         ▼        ▼         ▼        ▼          ▼
     chunk/   recovery/  identity/ share/   vault/   wal/      antientropy/
     (en/dec) (derive   (epoch    (KEM     (snap-   (sign     (sign root
              MK)        sigs)    wraps)   shot     WAL ops)  hashes)
                                           sigs)
```

## Inputs

- Plaintext bytes (only ever from chunks within the engine; never from a plugin).
- Keys held in memory.
- Per-call nonces (random where AEAD is fresh; deterministic-derived where required).

## Outputs

- Ciphertext + tag (to chunk/, share/, vault/).
- Subkeys (to chunk/, identity/, share/).
- Signatures (to wal/, vault/, identity/, share/).
- KEM-wrapped keys (to share/).

## Side effects

- The master key lives in memory while the vault is unlocked. On lock or shutdown, `zeroize` overwrites it. The key never persists in plaintext.
- On vault destruction, `zeroize` is called and the keystore wrapper is overwritten with random bytes.

## Invariants this module preserves

- **I1 (confidentiality)** — encrypt is called before any data leaves the engine boundary.
- **I2 (integrity)** — AEAD tag and signature verification refuse on mismatch.
- **I7 (deterministic cold start)** — KDF profile + salt are recorded in `Vault`, so re-derivation is deterministic.

## Implementation notes

- AEAD selection at vault creation time and stored in `Vault.aead_suite`. Switching AEAD requires explicit migration (re-encrypt during snapshot rotation).
- Nonce generation: random for chunk shards (96-bit OK because per-chunk keys avoid the birthday-bound problem). Never reuse a nonce with the same key.
- AAD: for chunks, `chunk_hash || shard_index`. This prevents shard substitution.
- Argon2id profile detected on first unlock and pinned in `Vault.kdf_params`. Lower-RAM devices get explicit warnings (no silent degradation).
- The `KeyPurpose` enum is closed; reserved slots are listed in [`DESIGN.md`](../../DESIGN.md) §8.1. Adding a new purpose requires a format-version bump.
- `zeroize` uses platform-specific guarantees (`mlock`, `explicit_bzero`, `SecureZeroMemory`); no compiler-eliminable writes.

## Tests

- Round-trip encrypt/decrypt for every AEAD mode.
- KDF determinism across repeated derivations from same passphrase.
- HKDF independence: different purposes produce uncorrelated subkeys.
- Sign/verify and KEM round-trip under known-answer test vectors.
- Zeroize: after `zeroize(mk)`, no plaintext key bytes remain in process memory (within OS guarantees).
