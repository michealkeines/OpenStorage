# share/ — Per-Recipient Share Manager

**Layer**: L4.
**Role**: implements the share half of `IdentityShareContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.10). Creates, accepts, and revokes shares; manages per-recipient key wraps; produces and consumes `share_blob` artifacts.

## What lives here

- `create_share(scope, recipient, perms, expires)` → `(Share, share_blob)`.
- `revoke_share(share_id)` → triggers file-key rotation + chunk re-encryption.
- `import_share(share_blob)` (recipient-side) → adds to inbox.
- `accept_share(share_id)` (recipient-side) → mounts under `/shared-with-me/...`.
- `list_outbound`, `list_inbox`.
- Optional: `republisher_hint` packaging into share_blob ([`DESIGN.md`](../../DESIGN.md) §15.1).

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (KEM encap/decap, signing), `identity/` (peer pubkeys), `metadata/`, `chunk/` (key rotation triggers re-encryption).
- Called by `api/`.

## Flow — Create Share

```
   API → POST /v1/vaults/{v}/shares { scope, recipients, perms, expires }
                          │
                          ▼
   share/.create_share:
     for each recipient peer_id:
       resolve peer's kem_pubkey via identity/
       crypto/.kem_encapsulate(peer.kem_pubkey, file_key) → wrapped_key + ciphertext
       wrapped_keys[].append({ recipient_id, wrapped_key, scheme: ml-kem-768, wrapped_at })
                          │
                          ▼
   wal/.append OrSetAdd on file.wrapped_keys for each recipient
   wal/.append OrSetAdd on shares (Share record with metadata)
                          │
                          ▼
   build share_blob:
     {
       share_id, scope, recipient_peer_id, wrapped_key,
       expires_at, signature_by_owner (epoch_id from identity/ chain),
       owner_chain_delta_since? : list of IdentityEpoch
                                  // optional; populated when owner has rotated
                                  // since the recipient's last seen owner-epoch
                                  // (recipient's last_seen_epoch is communicated
                                  //  out-of-band or assumed = epoch at add time)
       republisher_hint?  // optional, lists provider locators
     }
                          │
                          ▼
   crypto/.sign(share_blob, owner_sign_privkey of current epoch)
                          │
                          ▼
   ⟶ event share.created
   API returns share_blob; user transmits OOB to recipient
```

## Flow — Recipient Imports Share

```
   API → POST /v1/inbox/import { share_blob }
                          │
                          ▼
   share/.import_share:
     load Peer for owner_peer_id (refuse if unknown peer)
     if blob.owner_chain_delta_since present:
       identity/.extend_peer_chain(owner_peer_id, delta)  ← validates and appends
     locate epoch_id within Peer.epochs (refuse with peer_chain_outdated if missing)
     verify blob's signature against epoch.sign_pubkey
     refuse on any failure
                          │
                          ▼
   persist as inbox entry (Share-shaped record but in inbox column family)
                          │
                          ▼
   ⟶ event share.received
```

## Flow — Recipient Accepts Share

```
   API → POST /v1/inbox/{share_id}/accept
                          │
                          ▼
   share/.accept_share:
     crypto/.kem_decapsulate(my_kem_privkey from identity/, wrapped_key)
       → file_key
     persist this file_key locally so recipient can decrypt fetched chunks
                          │
                          ▼
   mount under /shared-with-me/<owner_label>/<scope_path>
                          │
                          ▼
   if republisher_hint present: optionally pin chunks to recipient's own backends
     (recipient fetches each chunk, re-puts as encrypted bytes via their own plugins,
      registers them in their own metadata as locally-pinned shared chunks)
                          │
                          ▼
   ⟶ event share.republished (if pinning)
```

## Flow — Revoke Share (owner-side)

```
   API → DELETE /v1/vaults/{v}/shares/{share_id}
                          │
                          ▼
   share/.revoke_share:
     for each affected file: rotate the file_key
       (derive new file_key from MK with a fresh chunk_index nonce)
                          │
                          ▼
     for each chunk in the file: re-encrypt with new chunk_key
       (this is a heavy operation — async; tracked via repair scheduler)
                          │
                          ▼
     remove the revoked recipient's wrapped_key entry (OrSetRemove)
     keep all other recipients' entries (rewrap them under new file_key)
                          │
                          ▼
   wal/.append the OrSetRemove + the rewraps
                          │
                          ▼
   ⟶ event share.revoked
   note: already-cached plaintext on the recipient's device cannot be recalled
```

## Inputs / Outputs

- Inputs: API requests; share_blobs (in/out of band).
- Outputs: persisted share records; key wraps; share_blob artifacts; events.
- Side: heavy file re-encryption on revocation.

## Invariants this module preserves

- **I1** — recipient can decrypt only via their KEM private key; owner doesn't transmit plaintext.
- **I5** — file-key rotation re-encrypts chunks; the new ciphertext replaces old via `chunk/`'s update path; old shards become shadows (not silent leaks).

## Implementation notes

- ML-KEM-768 ciphertext is ~1.1 KB per recipient — this is the per-share metadata cost.
- Peer fingerprint verification before wrapping is crucial to defend against typosquat / wrong-peer attacks.
- Revocation's re-encryption can take a long time on large files; the API returns immediately with a "revocation in progress" status; clients subscribe to events for completion.
- Republisher hint is opt-in; default is no hint, owner serves directly.
- A share's expiration is enforced at the recipient's side (their engine refuses to fetch chunks if expired) AND the owner's side stops serving on revocation; both layers are needed because either could be subverted.

## Tests

- Round-trip: create share → import → accept → recipient decrypts file successfully.
- Wrong recipient: import with mismatched signature is rejected.
- Revocation: after revoke, new chunk fetches fail to decrypt for revoked recipient (their wrapped_key is gone).
- Republisher: pinning produces a recipient-side copy that can be served when owner is offline.
- Concurrent share/revoke race: CRDT semantics resolve cleanly.
