# identity/ — Identity Epoch Chain

**Layer**: L4.
**Role**: implements the identity-management half of `IdentityShareContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.10). Owns the user's identity keypairs and the epoch chain that allows safe rotation.

## What lives here

- Identity = `{sign_pubkey: Ed25519, kem_pubkey: ML-KEM-768}` per epoch.
- Epoch chain: `epoch_n` is signed by `epoch_{n-1}`'s sign key.
- Peer registry: list of known peers' identities, with `verified` flag and fingerprint.
- Peer fingerprint computation (BLAKE3-160 of canonical pubkey CBOR).

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (sign + KEM key generation), `metadata/` (persist identity entity + chain).
- Used by `share/` for KEM wraps under recipient pubkey.
- Used by `vault/` to verify snapshot pointer signatures.
- Used by `recovery/` during cold-start verification.

## Flow — Initial Identity (epoch 0) at Vault Creation

```
   recovery/ creating vault
                          │
                          ▼
   identity/.create_identity():
     crypto/.derive_subkey(MK, kp:share-sign) → privkey for epoch 0 signing
     crypto/.derive_subkey(MK, kp:share-kem) → privkey for epoch 0 KEM
     compute fingerprint
     build IdentityEpoch { epoch: 0, sign_pubkey, kem_pubkey,
                          fingerprint, signed_by: <self-signed> }
     persist Identity entity with epochs = [epoch_0]
                          │
                          ▼
   record identity_pubkey_fingerprint in RecoveryManifest
```

## Flow — Identity Rotation (creating epoch n+1)

> **Hard serialization point**: identity rotation is the **one place** where the lease is enforced as a real lock, not advisory. Concurrent rotations from two devices would produce competing epoch_n+1 entries with different keypairs, both technically valid, fragmenting trust. We prevent that by requiring lease ownership.

```
   API → POST /v1/identities/self/rotate
                          │
                          ▼
   identity/.rotate_identity():
     check lease/.is_holder() → if not lease holder, fail with `lease_required`
                          │
                          ▼
     derive new subkeys for epoch n+1 (HKDF context bound to epoch index)
     compute new fingerprint
     sign (new sign_pubkey, new kem_pubkey) using epoch n's sign privkey
     append IdentityEpoch to chain
                          │
                          ▼
   wal/.append (OrSetAdd on identity.epochs)
   metadata/.commit_txn
                          │
                          ▼
     update RecoveryManifest.identity_chain (re-encrypt; re-push to vault providers)
     update VaultBinding.last_seen_anchor_fingerprint (unchanged — anchor is epoch_0)
                          │
                          ▼
   ⟶ event identity.epoch_rotated { from_epoch: n, to_epoch: n+1 }
                          │
                          ▼
   future snapshot pointers + share blobs use epoch n+1 keys
```

### Edge cases

- Non-lease-holder calls rotate: rejected with `lease_required`. UX should suggest "wait until your other device releases the lease, or take it over."
- Crash mid-rotation: WAL append is atomic. Either chain has new epoch (and rotation is durable) or it doesn't (and the user retries).
- Rotation while a peer is mid-share: the peer's already-signed share blob remains verifiable against the older epoch (which stays in the chain). Subsequent shares use new epoch.

## Flow — Cold-Start Chain Verification

```
   recovery/ unlocked, has RecoveryManifest with identity_pubkey_fingerprint
                          │
                          ▼
   identity/.verify_chain():
     fetch persisted identity_chain from metadata/
     verify fingerprint(epoch_0) == identity_pubkey_fingerprint in manifest
     for each subsequent epoch:
       verify signed_by_prev signature against previous epoch's sign_pubkey
                          │
                          ▼
     if any link fails:
       ⟶ event identity.chain_invalid { broken_at_epoch }
       refuse to operate on this vault until user intervenes
                          │
                          ▼
     return current valid epoch (last in chain)
```

## Flow — Add a Peer

The peer's identity blob carries their **full chain at sharing time**, not just epoch_0. Without this, a recipient cannot verify a share signed under any epoch beyond the one they observed at peer-add time.

```
   API → POST /v1/identities/peers
         body: peer's identity blob = {
           epoch_0 : IdentityEpoch (self-signed),
           ...    : IdentityEpoch (each signed_by_prev),
           epoch_n : IdentityEpoch
         }
                          │
                          ▼
   identity/.add_peer(blob):
     verify blob[0]'s self-signature (anchor)
     for i in 1..n: verify blob[i].signed_by_prev against blob[i-1].sign_pubkey
     fail if any link broken
                          │
                          ▼
     compute fingerprint = BLAKE3-160(epoch_0.sign_pubkey)  ← stable across rotations
     persist Peer { peer_id, epochs: blob, verified: false, last_seen_epoch: n, ... }
                          │
                          ▼
   user must call /verify with expected fingerprint OOB to set verified = true
```

## Flow — Extend Peer's Chain (chain delta on later shares)

When a peer rotates after we added them, the peer SHOULD include a "chain delta" in subsequent share blobs so we can extend our known chain trustworthily.

```
   share/.import_share(share_blob):
     blob carries:
       owner_peer_id
       chain_delta : list of IdentityEpoch (from our last_seen_epoch+1 to current)
       signed_by_owner : signature on the share content (using current epoch's sign key)
                          │
                          ▼
   identity/.extend_peer_chain(peer_id, chain_delta):
     load Peer
     verify each delta entry's signed_by_prev against the previous epoch
       (previous = last entry of Peer.epochs OR previous entry in the delta)
     append validated entries to Peer.epochs; update last_seen_epoch
                          │
                          ▼
     now share/.verify can succeed against current epoch's sign_pubkey
```

### Edge cases

- Chain delta has a gap (e.g., we have up to epoch 5, delta starts at epoch 7): refuse with `peer_chain_gap`. User must re-import full identity blob.
- Chain delta links don't verify (broken signed_by_prev): refuse; possible identity-blob tampering.
- Owner's identity rotated multiple times since the last share we got: subsequent shares should each carry the delta from our last_seen.

## Inputs / Outputs

- Inputs: vault creation, rotate command, peer add/verify commands.
- Outputs: identity records persisted; peer records persisted; events.
- Side: every share henceforth signs under current epoch.

## Invariants this module preserves

- **I7 (deterministic cold start)** — chain verification before any further operation; cold-start can't be tricked into trusting a forged identity.
- **I8** — peer pubkeys are user-verified out of band; no central directory, no MITM via the project's infrastructure.

## Implementation notes

- The chain is append-only; old epochs are not removed (they're needed to verify older shares).
- A share signed under epoch 5 remains verifiable forever as long as epoch 5's public key is in the chain.
- Rotation is a privacy/security hygiene operation; not required for normal use.
- KEM key rotation specifically affects future shares; existing shares signed under older epochs still decap with the older private key (which is stored wrapped under MK).
- Peer fingerprint is what the UX shows for OOB comparison; the canonical form is BLAKE3-160 of the canonical CBOR of the peer's `(sign_pubkey, kem_pubkey)`.

## Tests

- Initial identity round-trip.
- Rotation: chain extended; old keys still verify old signatures; new ones verify new.
- Chain forgery attempt: unsigned epoch insertion → verification fails.
- Peer add + verify flow.
- Cold-start verification across N rotations: still valid; broken link detected.
