# recovery/ — Recovery & Vault Lifecycle

**Layer**: L4.
**Role**: implements `RecoveryContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.9). Owns vault unlock, recovery flows, master-key rotation, vault destruction, and the local **VaultBinding** file used to bootstrap cold-start.

> **Honest limitation surfaced prominently**: recovery requires **both** (a) recovery materials AND (b) access to at least one of the cloud accounts holding the vault metadata. The materials decrypt the metadata; the cloud account hosts it. Materials alone are insufficient. Frontends must communicate this clearly at recovery configuration time and at recovery attempt time.

## What lives here

- Vault creation: derive MK, generate identity epoch 0, build recovery manifest, persist Vault entity.
- Unlock: derive MK from passphrase / Shamir / recovery file / hardware key.
- Recovery configuration: passphrase + (optional) recovery file + (optional) Shamir + (optional) hardware key. User-chosen, additive.
- Master-key rotation: rotate MK; rewrap recovery manifest; rewrap per-file keys; bump identity epoch (if simultaneous).
- Vault destruction: crypto-shred + best-effort delete sweep across all plugins + residual report.

## Boundaries

- Depends on `types/`, `entities/`, `crypto/`, `keystore/`, `vault/`, `repair/` (reuses worker pool for destruction sweep), `identity/`.
- Called by `api/` (unlock, configure recovery, destroy vault).

## Flow — Cold Start Unlock (revised; uses VaultBinding)

This is the **canonical** unlock path on a device that already has a VaultBinding (the vast majority of unlocks). The fresh-device case is in F-VL-2-bind below.

```
   API → POST /v1/vaults/{v}/unlock { method, materials }
                          │
                          ▼
   recovery/.unlock(method, materials):

     1. Read VaultBinding for {v} from local disk
        keystore/.unwrap → VaultBinding { providers, last_seen_pointer,
                                          last_seen_anchor_fingerprint, ... }
        if VaultBinding.last_seen_anchor_fingerprint is None:
          this is the first unlock after fresh-device bind (M-1 case).
          Cross-checks against cached anchor / pointer are SKIPPED below.
          They will be populated at the end of this flow.

     2. crypto/.derive_master_key(materials, kdf_params)
        (Shamir mode: combine shares first; HardwareKey: challenge-response;
         Passphrase: Argon2id)

     3. Each generated recovery token carries a recovery_token_id.
        If method's token_id ∉ RecoveryManifest.recovery_token_active_set:
          fail with `recovery_token_revoked` (see rotation below)

     4. Fetch RecoveryManifest from EVERY binding-listed provider (in parallel).
        For each successfully-fetched manifest:
          a. crypto/.decrypt(manifest, MK) — discard candidates that fail decrypt
          b. verify manifest.signature using manifest.signing_epoch_id's
             sign_pubkey from manifest.identity_chain
          c. verify manifest.identity_anchor_fingerprint matches
             BLAKE3-160(manifest.identity_chain[0].sign_pubkey)
        If VaultBinding.last_seen_anchor_fingerprint is Some:
          discard any manifest whose identity_anchor_fingerprint differs from
          the cached value (tamper signal; emit `provider.health_changed { state: suspect }`).
        If None (first unlock post-bind, M-1):
          accept any structurally-valid manifest; trust establishes from this unlock.
        Pick the manifest with the **highest version_counter** as authoritative.
        Discard older versions; emit `provider.health_changed { state: stale }`
        for any provider serving an older manifest.

     5. Walk manifest.identity_chain forward; verify each signed_by_prev
        Establish current_epoch = manifest.identity_chain.last

     6. vault/.fetch_signed_snapshot_pointer
        verify pointer.signature against current_epoch.sign_pubkey
        if VaultBinding.last_seen_pointer is Some:
          verify pointer.version_counter > VaultBinding.last_seen_pointer.version_counter
            (rollback detection)
        if None (first unlock post-bind): no rollback floor yet — accept

     7. vault/.fetch_and_decrypt_snapshot(pointer)
        metadata/.bulk_apply pages

     8. sync/.replay WAL since snapshot cutoff

     9. Update VaultBinding with current pointer + anchor fingerprint.
        On first-unlock-post-bind (M-1): populates the previously-None fields,
        completing the trust anchoring on this device.
        On subsequent unlocks: refreshes cached pointer if pointer advanced.
        keystore/.wrap and write back atomically (M-2 pattern; see keystore/FLOW.md).

    10. keystore/.store MK wrap key for fast subsequent unlocks this session

    11. Migrate any pending credentials from device_wrap → MK-wrap.
        plugin_host/.migrate_pending_credentials():
          for each pending entry:
            unwrap with device_wrap
            re-wrap under MK via kp:cred-wrap
            persist in metadata's permanent credentials column family
            delete from pending column family
        (idempotent — safe across crashes mid-migration)

   ⟶ event vault.unlocked
```

### Edge cases

- VaultBinding missing on this device → fall through to F-VL-2-bind (fresh-device flow).
- `recovery_token_revoked`: the token used has been rotated out. User must use a current token.
- Anchor fingerprint mismatch between VaultBinding and manifest: emit `provider.health_changed { state: suspect }` and `identity.chain_invalid`. Refuse to load.
- Pointer rollback (counter ≤ last seen): emit `provider.health_changed { state: suspect }`. Refuse to load.
- Manifest signature invalid (chain link broken): emit `identity.chain_invalid`. User must re-bind from another vault provider.

## Flow — Fresh Device Bind (F-VL-2-bind)

When a user installs OpenStorage on a new device and wants to recover their vault:

```
   1. User runs the setup wizard.
   2. wizard prompts: "Where is your vault?"
      User picks a plugin (e.g., Drive) and authorizes via OAuth.
      api/.providers/oauth/start → user OAuth → providers/oauth/complete
        ──► credentials_handle stored in keystore (NOT MK-wrapped yet, since no MK)

   3. recovery/.bind_vault(plugin_id, credentials_handle, vault_id):
        plugin_host/.invoke(plugin, peek, "recovery.manifest")
          → confirms a manifest exists for this vault_id
        write VaultBinding {
          vault_id, providers[primary], (no last_seen_pointer yet)
        }
        keystore/.wrap(VaultBinding, per_device_key)

   4. Now proceed with regular cold-start unlock (above flow), starting from step 2.
      The first successful decrypt populates last_seen_pointer + anchor.

   5. On unlock success: register this device in vault.allowed_devices via
      sync/.apply_local_op(OrSetAdd(allowed_devices, this device's pubkey))
```

### Edge cases

- Provider doesn't have a manifest at the expected path → either wrong vault_id, wrong provider, or vault never existed there. Surface options to user.
- Provider has manifest but MK derivation fails: wrong recovery materials. Provider data unchanged.
- Concurrent first-bind from two devices: each writes its own VaultBinding locally; both complete; both register themselves in allowed_devices via OrSetAdd (which merges cleanly).

## Flow — Vault Unlock (Shamir mode)

```
   API supplies k of n shares
                          │
                          ▼
   crypto/.shamir_combine(shares) → MK (or RecoveryFailure)
   then proceed as passphrase mode
```

## Flow — Vault Unlock (Hardware Key mode)

```
   API initiates challenge-response with hardware key (FIDO2 / Yubikey)
                          │
                          ▼
   hardware key signs the challenge → unwrap a stored half of MK
   combine with passphrase-derived half → MK
   proceed as passphrase mode
```

## Flow — Configure Recovery

```
   API → POST /v1/vaults/{v}/recovery/configure
                          │
                          ▼
   for each enabled mode:
     derive a wrapping key for that mode (or generate Shamir shares)
     wrap MK under each mode's key
     append wrapped_master_keys[] to RecoveryManifest
   metadata/.commit_txn (CRDT op: MapPut on recovery_modes)
                          │
                          ▼
   for "recovery_file" mode: present the file blob via one-time API URL
   for "shamir" mode: present the n shares to user once (then deleted from response)
```

## Flow — Recovery-Token Rotation (invalidate old shares / files)

A user who suspects a recovery token (a generated file or one Shamir share) has been compromised should rotate the token set without rotating MK. This produces fresh tokens and invalidates the old ones.

```
   API → POST /v1/vaults/{v}/recovery/rotate { mode: "shamir" | "recovery_file" | ... }
                          │
                          ▼
   recovery/.rotate_tokens(mode):
     for the chosen mode:
       generate new token_id(s)
       wrap MK under new token-derived keys (Shamir shares OR fresh recovery file)
       OrSetAdd new tokens to RecoveryManifest.recovery_token_active_set
       OrSetRemove old tokens (with their add_ids)
       bump RecoveryManifest.version_counter
       re-sign manifest with current identity epoch's sign key
                          │
                          ▼
     wal/.append the OR-Set ops + version_counter LWW update
     metadata/.commit_txn
                          │
                          ▼
     vault/.push_manifest_to_all_providers(new manifest)
       (if some providers lag, anti-entropy will catch them up;
        cold start picks the freshest by version_counter regardless)
                          │
                          ▼
     return new artifacts to caller (one-time URL or share blobs)
                          │
                          ▼
   ⟶ events: recovery.tokens_rotated { mode, new_count, revoked_count }
   ⟶ events: recovery.token_revoked { token_id } per old token
```

### Edge cases

- All tokens for a mode revoked simultaneously: that mode becomes inactive (no way to use it for unlock). At least one mode (typically passphrase) must remain active; engine refuses rotation that would leave zero active modes.
- Rotation mid-flight crash: WAL append is atomic; either all ops applied or none. Idempotency-Key on the API call ensures retry safety.
- Compromised token used between rotation initiation and propagation to all vault providers: brief window. The active set is consulted from the freshest vault replica; anti-entropy propagates the rotation to all replicas within `anti_entropy.exchange_interval`.

## Flow — Master-Key Rotation

```
   trigger: API → POST /v1/vaults/{v}/rotate-key
                          │
                          ▼
   crypto/.derive_master_key(new_passphrase, …) → MK_new
   crypto/.zeroize(MK_old)
                          │
                          ▼
   for each per-file key:
     unwrap with MK_old (already in memory)
     rewrap with MK_new
                          │
                          ▼
   re-derive vault_salt? optional, if user requested.
   re-encrypt RecoveryManifest's wrapped_master_keys under MK_new for each mode.
                          │
                          ▼
   metadata/ commit; emit identity.epoch_rotated if identity also rotated.
```

## Flow — Vault Destruction

```
   API → DELETE /v1/vaults/{v} (with confirmation)
                          │
                          ▼
   recovery/.destroy_vault():
     transition vault state → Destroying
     block new writes; reads served from cache only

     ── Phase 1: Chunk-backend artifacts ──
     enumerate all shards + all shadows from metadata/
     hand to repair/'s worker pool with destroy flag
                          │
                          ▼
     for each chunk-backend (provider, handle):
       plugin_host/.invoke(plugin, delete, handle)
       collect outcome (Removed | Tombstoned | Abandoned | NotSupported)

     ── Phase 2: Vault-provider artifacts (CR-4 fix) ──
     for each vault provider in VaultBinding.providers:
       enumerate everything under the vault's namespace at this provider:
         - snapshot.current pointer
         - snapshot.<ts>.delta and snapshot.<ts>.full blobs (all versions)
         - wal/<seq>.seg segments (all)
         - lease.json
         - merkle.root file
         - bloom.<id>.bin (if persisted)
         - recovery.manifest (after the next step uses it)
         - any other vault-namespaced files
       plugin_host/.invoke(plugin, delete, handle) for each
       collect outcomes
                          │
                          ▼
     ── Phase 3: Crypto-shred (the privacy guarantee) ──
     crypto/.zeroize(MK)
     overwrite RecoveryManifest with random bytes (then issue final delete attempt
       on the manifest at every vault provider — best effort; surviving randomized
       bytes are equivalent to deleted because they're unkeyed)
     keystore/.delete("mk_wrap_<vault_id>")
     keystore/.delete VaultBinding file from local disk
                          │
                          ▼
     ── Phase 4: Residual report ──
     build ResidualReport including BOTH:
       - chunk-backend shadows (Phase 1 outcomes)
       - vault-provider artifacts that couldn't be deleted (Phase 2 outcomes)
       grouped by driver_id with cached_elsewhere_risk per artifact
                          │
                          ▼
     transition vault state → Destroyed (terminal)
   ⟶ event vault.destroyed { residual_report }
   API returns 200 with the residual report
```

### Edge cases

- Crash mid-Phase-2: Phase 2 progress is checkpointed in the local pending-destruction state file. On restart, resume from last checkpoint. MK is already zeroized in Phase 3, so even partial Phase 1/2 leaves keyless ciphertext.
- Vault provider returns errors during Phase 2 (rate limit, auth fail): retry with backoff; eventually escalate to "permanent residual" in the report.
- VaultBinding lost between API call and execution: cannot enumerate vault providers. Report what we know; user must manually clean up vault providers via the cloud's own UI.

## Inputs / Outputs

- Inputs: passphrases / Shamir shares / recovery file / hardware-key responses; destroy commands.
- Outputs: MK in memory; updated RecoveryManifest; residual reports.
- Side: keystore writes; metadata mutations; events.

## Invariants this module preserves

- **I1, I2** — keys never leave the device; MK never persists without keystore wrapping.
- **I7 (deterministic cold start)** — recovery materials reconstruct the same MK that was originally generated.
- **I9 (honest accounting)** — residual report on destroy is exhaustive across all plugins and shadows.

## Implementation notes

- The "verify by decrypting check-blob" step makes wrong passphrases fail fast (no need to attempt full snapshot decrypt).
- Hardware-key mode integrates with WebAuthn / FIDO2 on desktop; with platform Passkey on mobile.
- Recovery file is just a CBOR blob containing a wrapped MK; user prints, scans, or stores at will.
- Shamir shares can be presented as paper / QR / PDF; library generates them on configuration and never stores them again.
- Vault destruction is *synchronous* in the API (returns the residual report); the actual delete sweep can complete asynchronously, with progress events.

## Tests

- Round-trip: configure modes → lock → unlock with each mode → MK matches.
- Shamir: k-1 shares fail; k succeed.
- Wrong passphrase: fast-fail without revealing partial info.
- Rotation: after rotation, old passphrase fails; new passphrase works; per-file keys still decrypt files.
- Destruction: after destroy, no MK derivable from any recovery material; surviving ciphertext on backends decrypts to garbage.
