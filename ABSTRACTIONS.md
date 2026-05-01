# OpenStorage — High-Level Abstractions

> **Purpose**: this document is the bridge between the narrative design and an executable implementation. It defines the types, interfaces, state machines, and data-flow primitives at a level high enough to draw any data flow diagram from, and low enough that an implementation maps onto it directly.
>
> **Read alongside**: [`DESIGN.md`](./DESIGN.md), [`PLUGIN_SDK.md`](./PLUGIN_SDK.md), [`API.md`](./API.md), [`RESILIENCE.md`](./RESILIENCE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md).
>
> **Reading guide**: §1 (layers) → §2–4 (data) → §5 (interfaces) → §6 (state machines) → §7 (CRDT ops) → §8 (data-flow primitives) → §9 (module map) → §10 (cross-cutting). Every later section references the earlier ones; read in order on first pass.

---

## 1. The Conceptual Layers

The system has six conceptual layers, numbered by **dependency depth**: a module's layer = `1 + max(layer of its dependencies)`. Every line of code, every diagram, every test belongs to exactly one layer.

> **Note**: this numbering was revised after a flow-tracing review found that an earlier "geographic" numbering placed `plugin_host/` and `events/` at positions inconsistent with their actual dependency profile. The convention now is **strict dependency depth**: a module that depends on metadata (L2) and crypto (L3) is at least L4, regardless of where it sits visually in the system diagram.

```
┌────────────────────────────────────────────────────────────────────┐
│  L6  FRONTEND        UX surface; consumes API; no engine state     │
│      cli │ gui │ fuse │ webdav-bridge                              │
├────────────────────────────────────────────────────────────────────┤
│  L5  API             auth, routing, streaming                      │
│      api                                                           │
├────────────────────────────────────────────────────────────────────┤
│  L4  CORE SERVICES   composed; orchestrate L3 primitives + L1/L2   │
│      vfs │ sync │ identity │ share │ repair │ antientropy │        │
│      recovery │ vault │ lease │ plugin_host                        │
├────────────────────────────────────────────────────────────────────┤
│  L3  CORE PRIMITIVES one job each, mostly pure                     │
│      chunk │ placement │ bloom │ merkle │ ec │ events              │
├────────────────────────────────────────────────────────────────────┤
│  L2  CORE STORAGE    the master persists here; algorithms over     │
│                      bytes & state                                 │
│      metadata │ wal │ keystore │ crypto                            │
├────────────────────────────────────────────────────────────────────┤
│  L1  FOUNDATION      no internal dependencies                      │
│      types │ entities                                              │
├────────────────────────────────────────────────────────────────────┤
│  L0  EXTERNAL        not part of the engine binary                 │
│      plugins │ backends                                            │
└────────────────────────────────────────────────────────────────────┘
```

### Layer Rules (enforceable)

1. **No upward calls.** A module MUST NOT depend on any module at a higher layer.
2. **Same-layer composition is allowed for primitives, not for orchestration loops.** L4 peers freely call each other's primitive operations (e.g., `vfs/` → `sync/.apply_local_op`). What's forbidden is *mutual orchestration*: `vfs/` triggering `repair/`'s background loop which calls back into `vfs/`. Background loops are triggered only by timers and events.
3. **L0 boundary is unidirectional.** `plugin_host/` (L4) is the only module that invokes L0 plugin code.
4. **Events are a primitive, not a service.** `events/` is L3; any L4+ module may emit; subscribers (api, internal observers) consume.
5. **Frontends speak only the API.** L6 may not link engine modules directly except in the embedded-library mode.
6. **Crypto is a primitive at L2, not L3.** Despite its conceptual feel as a "primitive operation set," `crypto/` is dependency-equivalent to `keystore/` and is needed by `wal/` for entry signing. Treating it as L2 keeps `wal/` (L2) compliant. This is consistent with the depth rule: crypto's only dependency is `keystore/` (L2) and `types/` (L1).

### Notable Repositioning Rationale

| Module | Was | Now | Reason |
|---|---|---|---|
| `plugin_host/` | L1 | **L4** | Depends on `metadata/` (L2) + `crypto/` (L2); orchestrates plugins; structurally a service. Its L0-facing role is geographic, not architectural. |
| `events/` | L5 | **L3** | Pure pub/sub; no orchestration; depended on by L4+ modules. A primitive, not a service. |
| `crypto/` | L3 | **L2** | Dependency-depth-equivalent to `keystore/`. `wal/` (L2) needs it for entry signing; the L3 placement was wrong. |
| `chunk/` | L3 | **L3 (re-scoped)** | Now strictly *transformative* (split / encrypt / ec_encode / ec_reconstruct / decrypt). Orchestration of placement + plugin calls moved to `vfs/` (L4). |
| `placement/` | L3 | **L3 (pure)** | Pool snapshot is *passed in* by the L4 caller (vfs/repair); placement does not reach into vault/. |

---

## 2. Identifiers

Every persistent thing in the system has an identifier. These are the primary keys.

| Identifier | Form | Generated by | Used as primary key for | Notes |
|---|---|---|---|---|
| `VaultId` | UUIDv7 | engine on vault creation | Vault entity | One vault = one logical namespace. |
| `FileId` | UUIDv7 | VFS on file creation | File entity | Stable across renames. |
| `ChunkHash` | 32 bytes (BLAKE3-256) | Chunk Engine; hash of `(vault_salt \|\| plaintext)` by default, or `BLAKE3(plaintext)` in legacy mode | Chunk entity | Content-addressed; used for dedup within a vault. |
| `ShardId` | derived: `H(chunk_hash, shard_index)` | Chunk Engine | Shard entity | Stable; lets the engine refer to a shard without knowing where it lives. |
| `ShadowId` | UUIDv7 | engine when registering a shadow | Shadow entity | One per orphaned ciphertext object. |
| `DeviceId` | UUIDv7 | engine on first run on a device | Device entity | Paired with `Ed25519` device sign key. |
| `PeerId` | string `"peer:" + base32(BLAKE3-160(sign_pubkey))` | engine when adding a peer | Peer entity | Fingerprint-shaped; stable across the peer's epoch rotations until they re-keypair fully. |
| `IdentityId` | string `"id:" + base32(BLAKE3-160(epoch_0_sign_pubkey))` | engine on vault creation | Identity entity | One per vault owner; epoch chain extends from here. |
| `ShareId` | UUIDv7 | engine on share creation | Share entity | |
| `ProviderId` | UUIDv7 | engine when user adds a configured plugin instance | Provider entity | One per *instance*; same plugin can have multiple. |
| `PluginId` | reverse-DNS string (manifest) | plugin author | Plugin entity | E.g., `org.openstorage.drive`. |
| `EpochId` | u32, monotonically increasing | engine on identity rotation | Epoch within identity chain | |
| `RecoveryManifestId` | UUIDv7 | engine on recovery configuration | RecoveryManifest entity | |
| `RecoveryTokenId` | UUIDv7 | engine on each token generation (file/Shamir/hardware-key wrap) | recovery_token_active_set membership; embedded in the generated artifact | Rotation invalidates by removing from the active set. |
| `LocalKvKey` | opaque bytes | engine when storing oversized op values | resolves via metadata KV | Used by `LwwRegisterIndirect`. |
| `LeaseId` | UUIDv7 | engine on lease acquisition | Lease record | Renewed without changing id. |
| `WalEntryId` | `(device_id, seq)` composite | engine on every WAL append | WAL entry | seq is monotonic per device. |
| `IdempotencyKey` | UUID supplied by caller | frontend / engine | client-side dedupe | 24 h retention. |
| `CredentialsHandle` | opaque bytes (≤ 64) | engine after OAuth | refers to wrapped credentials | Plugins receive this; never the raw token. |

---

## 3. Value Types (data without identity)

These are pure values, used as fields of entities or as parameters to operations.

### 3.1 Time and Causality

| Type | Form | Purpose |
|---|---|---|
| `Hlc` | record `{physical: u64 ms, logical: u32}` | Hybrid logical clock; orders WAL ops across devices. |
| `Timestamp` | RFC 3339 with ms (UTC) | Wall-clock timestamps for human-facing fields. |
| `MonotonicCounter` | u64 | For snapshot version counters; never decreases. |
| `Duration` | ISO 8601 form | TTLs and intervals. |

### 3.2 Cryptographic

| Type | Form | Purpose |
|---|---|---|
| `BlakeHash` | 32 bytes | Content addressing, integrity. |
| `AeadNonce` | 12 bytes (ChaCha20-Poly1305 / GCM) or 24 (XChaCha) | Per-shard. |
| `AeadTag` | 16 bytes | AEAD authentication tag. |
| `Ed25519Sig` | 64 bytes | Signatures (lease, snapshot, shares, WAL ops). |
| `Ed25519Pub` / `Ed25519Priv` | 32 / 32 bytes | Identity, device, lease keys. |
| `MlKemPub` / `MlKemPriv` | ~1.2 KB / ~2.4 KB | Recipient KEM public/private. |
| `MlKemCiphertext` | ~1.1 KB | KEM-encapsulated key. |
| `WrappedKey` | record `{scheme, ciphertext, recipient_id, wrapped_at}` | A file key wrapped under one recipient's public key. |
| `KeyPurpose` | enumerated string (e.g., `kp:file`, `kp:share-kem`) | HKDF info parameter. |
| `KdfParams` | record `{algo, memory_kib, iterations, parallelism, salt}` | Argon2id profile. |

### 3.3 Capacity and Health

| Type | Form | Purpose |
|---|---|---|
| `ECScheme` | record `{k: u8, n: u8}` | k-of-n Reed–Solomon scheme. |
| `ReplicationFactor` | u8 | Used when `redundancy.mode = replication`. |
| `HealthScore` | float ∈ [0.0, 1.0] | Per-plugin and per-shard summary. |
| `QuotaState` | record `{total: Option<u64>, used: Option<u64>, untrusted: bool}` | Per-plugin capacity report. |
| `RateLimitState` | record `{remaining: u32, reset_at: Timestamp}` | Per-plugin throttle. |
| `LatencyProfile` | record `{p50_ms, p95_ms, p99_ms}` | Drives hedge thresholds. |
| `Tier` | enum `Hot \| Warm \| Cold` | Per-chunk classification. |

### 3.4 Trust and Legal

| Type | Form | Purpose |
|---|---|---|
| `TrustCorrelationGroup` | string (e.g., `google`, `microsoft`) | Diversity rule. |
| `LegalClass` | enum `Green \| Yellow \| Red` | ToS posture. |
| `CachedElsewhereRisk` | enum `Low \| Medium \| High` | Backend-reported risk that bytes survive in third-party caches. |
| `DurabilityClass` | enum `Ephemeral \| Weekly \| Yearly \| Archival` | Plugin-declared retention. |

### 3.5 Plugin Interaction

| Type | Form | Purpose |
|---|---|---|
| `Capability` | enum (closed set; see PLUGIN_SDK §6) | Single capability flag. |
| `CapabilitySet` | bag of `Capability` + scalar values | Full capability declaration. |
| `PriorHandleState` | enum `Overwritten \| Removed \| Tombstoned \| Abandoned \| Unknown` | Returned from `put` when `replaces_handle` was supplied. |
| `DeleteOutcome` | enum `Removed \| Tombstoned \| Abandoned \| NotSupported \| NotFound` | Returned from `delete`. |
| `QuotaReclaimed` | enum `Yes \| No \| Unknown` | Per-op reclaim status. |
| `Range` | record `{start: u64, end: u64}` | For range reads. |

### 3.6 Errors

| Type | Form | Purpose |
|---|---|---|
| `ErrorCode` | enumerated (see API §16, PLUGIN_SDK §9) | Stable taxonomy. |
| `Error` | record `{code, message, retryable, retry_after, details, correlation_id}` | Standard error envelope. |

---

## 4. Entity Types

These are records with identity, lifecycle, and relationships. The model below is the single source of truth; conflicts with prose elsewhere should be resolved against this section.

### 4.1 Vault

```
Vault
├ vault_id : VaultId
├ format_version : u32
├ owner : IdentityId
├ created_at : Timestamp
├ aead_suite : enum { ChaCha20Poly1305, Aes256Gcm }
├ kdf_params : KdfParams
├ vault_salt : 32 bytes        ← for chunk-hash salting
├ recovery_manifest_ref : RecoveryManifestId
├ snapshot_pointer : SignedSnapshotPointer
├ lease_path : opaque (vault provider name)
├ allowed_devices : OrSet<DeviceAuthorization>  ← was DeviceId; now HLC-windowed
├ identity_chain : list of IdentityEpoch
└ merkle_root : BlakeHash
```

### 4.2 File

```
File
├ file_id : FileId
├ path : string                     ← namespace key, CRDT-managed via PATH_MOVE ops
├ size_bytes : u64                  ← LWW_REGISTER
├ created_at : Timestamp            ← LWW_REGISTER
├ modified_at : Timestamp           ← LWW_REGISTER
├ permissions : Permissions          ← LWW_REGISTER
├ content_type : string             ← LWW_REGISTER
├ tier_pinned : Option<Tier>        ← LWW_REGISTER (None = derived from access)
├ inline_payload : Option<InlineBlob>  ← exclusive with chunk_list
├ chunk_list : Option<list<ChunkHash>>
├ wrapped_keys : OrSet<WrappedKey>  ← per-recipient
├ acl : OrSet<AclEntry>
└ exists : LwwRegister<bool>        ← deletion flag
```

```
InlineBlob
├ ciphertext : bytes
├ nonce : AeadNonce
└ tag : AeadTag
```

### 4.3 Chunk

```
Chunk
├ chunk_hash : ChunkHash             ← primary key
├ plaintext_length : u64
├ ec_scheme : ECScheme
├ shard_list : list of ShardId
├ refcount : Counter                 ← CRDT counter
├ replication_state : enum { Full, Degraded, Recovering, Lost }
├ last_scrubbed_at : Timestamp
├ access_count_window : Counter
└ tier : Tier                        ← derived; cached
```

### 4.4 Shard

```
Shard
├ shard_id : ShardId
├ chunk_hash : ChunkHash             ← back-pointer
├ shard_index : u8
├ encryption_nonce : AeadNonce
├ encryption_tag : AeadTag
├ ciphertext_length : u64
├ driver_id : ProviderId             ← LWW_SET with previous_value (Case 6 fix)
├ native_handle : opaque bytes       ← LWW_SET with previous_value
├ stored_at : Timestamp
├ last_verified_at : Timestamp
├ health_score : HealthScore
└ ack_state : enum { Acked, InFlight, Failed }
```

### 4.5 Shadow

```
Shadow
├ shadow_id : ShadowId
├ original_chunk_hash : ChunkHash    ← informational
├ driver_id : ProviderId
├ native_handle : opaque bytes
├ ciphertext_length : u64
├ abandoned_at : Timestamp
├ reason : enum { UpdateReplaced, RepairReplaced, DeletionOrphaned, ConcurrentUpdateDemoted }
├ cached_elsewhere_risk : CachedElsewhereRisk
├ counts_against_quota : bool
└ tombstone_clears_at : Option<Timestamp>
```

### 4.6 Provider (chunk role) and VaultProvider (vault role)

```
Provider
├ provider_id : ProviderId
├ plugin_id : PluginId               ← which plugin code drives it
├ instance_label : string             ← user-facing
├ credentials_handle : CredentialsHandle
├ capabilities : CapabilitySet
├ legal_class : LegalClass
├ trust_correlation_group : TrustCorrelationGroup
├ quota : QuotaState
├ rate_limit : RateLimitState
├ health : HealthScore
├ latency : LatencyProfile
└ untrusted_quota : bool
```

```
VaultProvider
├ provider_id : ProviderId
├ plugin_id : PluginId
├ priority : enum { Primary, Replica }
├ credentials_handle : CredentialsHandle
├ last_synced_at : Timestamp
└ merkle_root_etag : opaque
```

### 4.7 Identity, Peer, Device, Share

```
Identity (the user's own)
├ identity_id : IdentityId
└ epochs : list of IdentityEpoch

IdentityEpoch
├ epoch : EpochId
├ sign_pubkey : Ed25519Pub
├ kem_pubkey : MlKemPub
├ fingerprint : BlakeHash
├ created_at : Timestamp
├ wrapped_privkeys : bytes           ← under MK
└ signed_by_prev : Option<Ed25519Sig> ← except epoch 0
```

```
Peer
├ peer_id : PeerId
├ epochs : list of IdentityEpoch     ← peer's full known chain;
│                                      seeded at add_peer time;
│                                      extended by chain-deltas
│                                      received in subsequent shares
├ label : string
├ verified : bool                    ← OOB fingerprint check
│                                      (compares peer.epochs[0].fingerprint)
├ last_seen_epoch : EpochId          ← highest epoch we've verified for this peer
└ added_at : Timestamp

Device
├ device_id : DeviceId
├ device_label : string
├ device_pubkey : Ed25519Pub          ← signs WAL ops
├ first_seen_at, last_seen_at
└ revoked_at : Option<Timestamp>      ← informational; the authoritative
                                        revocation record is in
                                        Vault.allowed_devices below

DeviceAuthorization
├ device_id : DeviceId
├ device_pubkey : Ed25519Pub          ← redundant with Device.device_pubkey
│                                       but cached here so WAL-replay
│                                       can verify signatures without
│                                       loading Device records
├ authorized_from_hlc : Hlc           ← lower bound; entries below this
│                                       HLC from this device are rejected
└ revoked_at_hlc : Option<Hlc>        ← upper bound; entries at-or-above
                                        this HLC are rejected
```

A WAL entry signed by device X is accepted if and only if:
- X has an entry in `allowed_devices`, AND
- `entry.hlc >= X.authorized_from_hlc`, AND
- `X.revoked_at_hlc is None OR entry.hlc < X.revoked_at_hlc`.

This makes revocation HLC-aware: entries authored *before* revocation remain valid; entries authored *at or after* revocation are rejected. Without this, fresh-device cold-start replay would drop legitimate writes from a since-revoked device.

```
Share
├ share_id : ShareId
├ scope : enum Scope { File(path), Folder(path), Vault }
├ recipient : PeerId
├ permissions : list of Permission
├ wrapped_keys_ref : reference into File.wrapped_keys
├ created_at : Timestamp
├ expires_at : Option<Timestamp>
└ revoked_at : Option<Timestamp>
```

### 4.7a VaultBinding (per-device, outside encrypted metadata)

The local-disk file that breaks the cold-start vault provider bootstrap. Stored under the OS user dir, encrypted with a per-device wrap key from `keystore/`. NOT encrypted under MK (we need it before we have MK).

```
VaultBinding
├ vault_id : VaultId
├ providers : list of {                 ← which vault providers hold the metadata
│   plugin_id : PluginId                  for this vault on this device
│   credentials_handle : CredentialsHandle
│   priority : enum { Primary, Replica }
│   added_at : Timestamp
│   }
├ last_seen_snapshot_pointer : Option<SignedSnapshotPointer>
│                                       ← None until first successful unlock
│                                         after bind; thereafter cached for
│                                         rollback detection on cold start
├ last_seen_identity_anchor_fingerprint : Option<BlakeHash>
│                                       ← None until first successful unlock
│                                         after bind; thereafter cached for
│                                         trust pre-check
├ device_id : DeviceId                  ← this device's identifier
├ format_version : u32
├ created_at : Timestamp                ← when this binding file was created
└ updated_at : Timestamp
```

**Initial-state rule (M-1)**: On fresh-device bind, the engine cannot decrypt the manifest (no MK yet). Both `last_seen_snapshot_pointer` and `last_seen_identity_anchor_fingerprint` are written as `None`. The first successful unlock populates them from the freshest manifest the engine fetches. Cross-check on cold-start is **skipped** when these fields are None (the post-bind first-unlock case); all subsequent unlocks cross-check normally.

This creates a **brief one-time trust window** at first unlock: the engine cannot verify the manifest's anchor against a cached value because there isn't one. The single point of trust during this window is the user's recovery materials (which decrypt the manifest); any tampering with the manifest body is caught by AEAD verification, and any forgery is caught by the embedded chain's self-consistency. The user should be informed in setup-wizard UX that "the first unlock anchors trust on this device."

**Lifecycle**:
- Created when a user first binds a vault on a device (after pairing the first vault provider via OAuth + `recovery/.bind_vault`).
- Updated atomically when the user adds/removes vault providers, when a snapshot pointer advances, or when identity rotates.
- Re-created on a fresh device after the user re-pairs the first vault provider through the setup wizard.
- Deleted when the user unbinds the vault from this device (note: vault not destroyed — just unbound from this device).

**Trust model**:
- Tampering is mitigated by per-device `keystore/` wrapping (other local users on the same OS account can't read it).
- Cross-checks the `identity_anchor_fingerprint` against the manifest after fetch — a tampered binding can redirect to a malicious vault provider, but the manifest from there will fail to decrypt under the user's MK.
- Loss of the binding file = re-pair flow (user goes through setup wizard again on this device).

### 4.8 Recovery, Lease, Snapshot

```
RecoveryManifest
├ manifest_id : RecoveryManifestId
├ format_version : u32
├ version_counter : MonotonicCounter              ← bumps on every change
│                                                   (rotation, MK rotation,
│                                                    chain extension, etc.)
├ signing_epoch_id : EpochId                      ← which identity epoch signed
│                                                   the version_counter+payload
├ signature : Ed25519Sig                          ← over canonical encoding of
│                                                   { manifest_id, version_counter,
│                                                     all body fields below }
│                                                   using identity epoch's sign key
├ modes : list of RecoveryMode
├ wrapped_master_keys : list of WrappedMasterKey   ← one per active mode
├ identity_anchor_fingerprint : BlakeHash         ← BLAKE3-160 of epoch_0 sign_pubkey
├ identity_chain : list of IdentityEpoch          ← FULL chain — required to break
│                                                   cold-start circular dependency
└ recovery_token_active_set : OrSet<RecoveryTokenId>  ← active tokens; rotation
                                                        invalidates by removing
                                                        token_id from the set
                                                        (each generated file/share
                                                         carries its token_id)
```

**Why both AEAD and signature on the manifest (M-5)?** The manifest is AEAD-encrypted under MK and additionally signed by the current identity epoch's sign key. This is intentional defense-in-depth:

- **AEAD alone** protects against attackers who don't have MK. Confidentiality and integrity within a single key.
- **Signature alone** would protect against forgery but not confidentiality.
- **Both together** also protect the narrow case of "attacker has MK but not the identity sign key" — for example, if MK leaks via a side channel (process-memory dump, weak RNG, cold-boot) but the identity sign key is hardware-bound (Yubikey, secure element). Without the signature, such an attacker could decrypt the manifest, re-encrypt their forgery under MK (whose AEAD they can compute), and serve it to vault providers. With the signature, that forgery is rejected by cold-start at the chain-validation step.

This layered protection costs ~64 bytes per manifest update (one Ed25519 signature) — negligible.

```
RecoveryMode (sum)
├ Passphrase
├ RecoveryFile  { fingerprint }
├ Shamir        { k: u8, n: u8 }
└ HardwareKey   { device_descriptor }

LeaseRecord
├ holder_device_id : DeviceId
├ acquired_at : Timestamp
├ expires_at : Timestamp
├ renewal_count : u32
└ holder_signature : Ed25519Sig

SignedSnapshotPointer
├ snapshot_id : opaque
├ version_counter : MonotonicCounter
├ epoch_id : EpochId
├ format_version : u32
├ created_at : Timestamp
└ signature : Ed25519Sig
```

### 4.9 WAL Entry, Snapshot Page

```
WalEntry
├ wal_id : (DeviceId, seq)
├ hlc : Hlc
├ device_id : DeviceId
├ op : Op                         ← see §7
├ signature : Ed25519Sig
└ idempotency_key : Option<IdempotencyKey>

SnapshotPage
├ page_id : opaque
├ page_version : MonotonicCounter
├ payload_kind : enum { FileRecords, ChunkRecords, Namespace, Shadows, … }
├ payload_codec : enum { CborV1, CborV2, … }
└ payload_bytes : opaque
```

### 4.10 Entity Relationship Map

```
                 ┌──────────────┐
                 │    Vault     │
                 └──┬──────┬────┘
                    │      └──── Identity (chain) ─── Peer (knows about)
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
       File ─── wrapped_keys ──► (recipient PeerId)
        │
        │ chunk_list
        ▼
      Chunk
        │ shard_list
        ▼
      Shard ───── driver_id ───► Provider (chunk role)
                                          │
                                  plugin_id│
                                          ▼
                                       Plugin
                                          │
                                          ▼
                                       Backend (external)
                       ▲
       Shadow ─────────┘ (refers to provider+handle that
                            we no longer reference)

       VaultProvider (separate role) ◄── Vault.snapshot_pointer
       LeaseRecord    ─── stored at vault path lease_path
       Device         ◄── allowed_devices on Vault
       Share          ◄── owns wrapped_keys entry by recipient
       RecoveryManifest ◄── recovery_manifest_ref on Vault
       WalEntry, SnapshotPage      transit / persistence
```

---

## 5. Interfaces (Operation Contracts)

This section defines the *abstract* interfaces between layers. Each interface is a set of operations, each operation has typed inputs and outputs. The implementation will realize them as Rust traits or service objects; this document is language-neutral.

### 5.1 Plugin Contract (the five ops, plus role-specific)

(Full detail in [`PLUGIN_SDK.md`](./PLUGIN_SDK.md). Summarized here for completeness.)

```
interface PluginContract:
  put(payload: bytes,
      hint: PutHint)
        → (handle: opaque,
           handle_changed: bool,
           prior_handle_state: Option<PriorHandleState>,
           stored_at: Timestamp,
           quota_reclaimed: QuotaReclaimed,
           tombstone_clears_at: Option<Timestamp>)

  get(handle: opaque, range: Option<Range>)
        → (ciphertext: bytes_stream)

  peek(handle: opaque)
        → (exists: bool, size: u64, mtime: Timestamp, etag: Option<BlakeHash>)

  delete(handle: opaque)
        → (outcome: DeleteOutcome,
           quota_reclaimed: QuotaReclaimed,
           cached_elsewhere_risk: CachedElsewhereRisk,
           tombstone_clears_at: Option<Timestamp>)

  health()
        → (state: enum, quota: QuotaState, rate_limit: RateLimitState,
           latency: LatencyProfile)

interface VaultPluginContract extends PluginContract:
  list(prefix: string, limit: u32, cursor: Option<opaque>)
        → (entries, next_cursor)

  cas_write(name: string, payload: bytes, expected_etag: Option<BlakeHash>)
        → (outcome: enum, new_etag: BlakeHash)
```

### 5.2 Crypto

```
interface CryptoContract:
  derive_master_key(passphrase, kdf_params, salt) → MasterKey
  derive_subkey(MasterKey, KeyPurpose, optional context) → Subkey
  derive_chunk_key(file_key, chunk_index) → ChunkKey
  encrypt(plaintext, key, nonce, aad) → (ciphertext, tag)
  decrypt(ciphertext, key, nonce, aad, tag) → plaintext or AuthFailure
  sign(privkey, message) → Ed25519Sig
  verify(pubkey, message, sig) → bool
  kem_encapsulate(MlKemPub, plaintext) → (ciphertext, shared_secret)
  kem_decapsulate(MlKemPriv, ciphertext) → shared_secret
  zeroize(MasterKey)            ← crypto-shred
```

### 5.3 Chunk Engine

```
interface ChunkEngineContract:
  split(file_stream, policy: ChunkingPolicy) → stream of (Chunk, Plaintext)
  pack_inline(plaintext, file_key) → InlineBlob
  ec_encode(ciphertext, ECScheme) → list of Shard ciphertexts
  ec_reconstruct(shards: K of N) → ciphertext
  hash(plaintext, vault_salt: Option<bytes>) → ChunkHash
```

### 5.4 Placement

```
interface PlacementContract:
  pick_shards_for_chunk(
    chunk_hash: ChunkHash,
    ec_scheme: ECScheme,
    pool: list of Provider,
    diversity: DiversityPolicy,
    tier: Tier
  ) → list of (shard_index, ProviderId)

  evaluate_rebalance_targets(chunk_hash) → list of (shard_index, target_ProviderId)

  effective_capacity(pool) → u64
```

### 5.5 Vault Manager

```
interface VaultManagerContract:
  fetch_snapshot(vault_provider) → SignedSnapshotPointer + snapshot data
  push_snapshot(vault_provider, delta_or_full) → ack
  fetch_wal_segments(vault_provider, since_seq) → stream of WalEntry
  push_wal_segment(vault_provider, segment) → ack
  acquire_lease(vault_provider, ttl) → LeaseRecord
  renew_lease(vault_provider, lease) → LeaseRecord
  release_lease(vault_provider, lease)
  reconcile_with_replicas() → ReconcileReport
```

### 5.6 Sync (CRDT)

```
interface SyncContract:
  apply_local_op(Op) → WalEntry
  apply_remote_wal_segment(stream of WalEntry) → MergeReport
  current_hlc() → Hlc
  generate_hlc(after_seen_remote: Option<Hlc>) → Hlc
```

### 5.7 Repair Scheduler

```
interface RepairContract:
  enqueue(chunk_hash, source: enum, urgency: u32)
  drain_one() → RepairTask
  on_complete(task, outcome)
  current_state() → { queue_depth, in_flight, by_source }
```

### 5.8 Anti-Entropy

```
interface AntiEntropyContract:
  build_local_merkle() → BlakeHash
  exchange_with(vault_provider) → DivergenceReport
  walk_divergent_subtree(vault_provider, path) → list of (page_id, page_version)
  pull_pages(vault_provider, list of page_id) → stream of SnapshotPage
```

### 5.9 Recovery

```
interface RecoveryContract:
  configure(modes: list of RecoveryMode) → RecoveryManifest
  attempt_recover(materials: RecoveryMaterials) → MasterKey or RecoveryFailure
  rotate_master_key() → new MasterKey
  destroy_vault() → ResidualReport
```

### 5.10 Identity & Share

```
interface IdentityShareContract:
  create_identity() → IdentityEpoch (epoch 0)
  rotate_identity() → IdentityEpoch (next epoch, signed by prev)
  add_peer(public_blob) → Peer
  verify_peer(peer_id, expected_fingerprint) → bool
  create_share(scope, recipient, perms, expires) → (Share, share_blob)
  revoke_share(ShareId) → KeyRotationPlan
  import_share(share_blob) → Share
```

### 5.11 VFS

```
interface VfsContract:
  open(path, mode) → FileHandle
  read(FileHandle, range) → stream of bytes
  write(FileHandle, range, bytes) → ack
  truncate(FileHandle, size)
  close(FileHandle)
  stat(path) → FileMetadata
  list_dir(path, cursor) → list of DirEntry
  rename(src, dst) → PATH_MOVE op
  unlink(path)
```

### 5.12 API Server

```
interface ApiServerContract:
  bind(transport: Uds | Tls)
  authenticate(token) → AuthSubject or Unauthenticated
  route(request) → handler
  stream_request_body(req) → stream of bytes
  stream_response_body(resp, stream)
  publish_event(event) → fanned out to subscribers
  subscribe(client, filter) → event stream
```

### 5.13 Plugin Host

```
interface PluginHostContract:
  load(plugin_manifest) → PluginInstance
  unload(PluginInstance)
  invoke(PluginInstance, op_name, args) → result   (sandboxed for 3rd-party)
  signed_fetch(credentials_handle, http_request) → http_response
  emit_log(PluginInstance, structured log entry)
```

### 5.14 Metadata Store

```
interface MetadataStoreContract:
  begin_txn() → Txn
  get(key) → Option<bytes>
  put(key, bytes)
  delete(key)
  scan(prefix, cursor) → stream of (key, bytes)
  commit(Txn)
  abort(Txn)
  snapshot_pages_dirty_since(seq) → stream of SnapshotPage
```

---

## 6. State Machines

The named state machines in the system. Every diagram in DESIGN.md eventually reduces to transitions among these.

### 6.1 Shard Lifecycle

```
                  ┌──────────┐
                  │  Staged  │
                  └────┬─────┘
                       │ placement assigns
                       ▼
                  ┌──────────┐
                  │ Placing  │
                  └────┬─────┘
                       │ ack from plugin
                       ▼
                  ┌──────────┐
              ┌──►│  Healthy │◄──── repair completes
              │   └────┬─────┘
              │        │ verify fail / scrub fail / read-repair detect
              │        ▼
              │   ┌──────────┐
              │   │ Degraded │── enqueued in repair scheduler
              │   └────┬─────┘
              │        │ repair places fresh shard
              └────────┘
                       │
                       │ EC threshold breached at chunk level
                       ▼
                  ┌──────────┐
                  │   Lost   │
                  └──────────┘
                  ┌──────────┐
                  │   Free   │  refcount = 0; scheduled deletion
                  └──────────┘
                       ↓
                       (delete result routes to Removed | Tombstoned | Abandoned;
                        Tombstoned/Abandoned register a Shadow record)
```

### 6.2 Plugin Lifecycle

```
   ┌─────────┐
   │ Loaded  │  manifest verified, sandbox ready, no state
   └────┬────┘
        │ init(settings, credentials_handle)
        ▼
   ┌─────────┐
   │  Init   │  plugin probes provider
   └────┬────┘
        │ ready
        ▼
   ┌─────────┐  ◄────────────┐
   │  Ready  │               │ resume
   └────┬────┘               │
        │ ops invoked        │
        ▼                    │
   ┌─────────┐          ┌────┴────┐
   │ Active  │          │ Paused  │  host throttles or quarantines
   └────┬────┘          └────▲────┘
        │ pause              │
        └────────────────────┘
        │ shutdown
        ▼
   ┌─────────┐
   │ Closing │
   └────┬────┘
        ▼
   ┌─────────┐
   │ Closed  │
   └─────────┘
```

### 6.3 Vault State

```
   ┌────────────┐
   │ Uncreated  │──── create(passphrase, recovery, providers) ───┐
   └────────────┘                                                │
                                                                 ▼
                                                          ┌─────────────┐
                                                          │   Locked    │ ◄────┐
                                                          └──────┬──────┘      │
                                                                 │ unlock      │ lock
                                                                 ▼             │
                                                          ┌─────────────┐      │
                                                          │  Unlocking  │      │
                                                          └──────┬──────┘      │
                                                                 │ MK derived, │
                                                                 │ snapshot    │
                                                                 │ loaded      │
                                                                 ▼             │
                                                          ┌─────────────┐      │
                                                          │  Unlocked   │ ─────┘
                                                          └──┬──────┬───┘ idle  ┌─────────┐
                                                             │      │  ────────►│ Locking │
                                                             │      │           └────┬────┘
                                                             │      │                │
                                                             │      │ destroy        │
                                                             │      ▼                │
                                                             │  ┌─────────────┐      │
                                                             │  │ Destroying  │      │
                                                             │  └──────┬──────┘      │
                                                             │         │ sweep done  │
                                                             │         ▼             │
                                                             │  ┌─────────────┐      │
                                                             │  │  Destroyed  │      │
                                                             │  └─────────────┘      │
                                                             └─── (terminal — no recovery from here)
```

#### Operations Allowed Per State

| Operation | Uncreated | Locked | Unlocking | Unlocked | Locking | Destroying | Destroyed |
|---|---|---|---|---|---|---|---|
| create | ✓ | — | — | — | — | — | — |
| unlock | — | ✓ | (in-flight) | — | — | — | — |
| read file | — | from cache only* | — | ✓ | from cache only* | from cache only* | — |
| write file | — | — | — | ✓ | rejected | rejected | — |
| share/revoke | — | — | — | ✓ | rejected | rejected | — |
| add/remove provider | — | — | — | ✓ | — | — | — |
| repair (background) | — | — | — | ✓ | continues, completes pending | continues for sweep | — |
| snapshot push | — | — | — | ✓ | flush + stop | — | — |
| anti-entropy | — | — | — | ✓ | — | — | — |
| lease acquire | — | — | — | ✓ | release | — | — |
| destroy | — | — | — | ✓ | — | (in-flight) | — |
| lock | — | (no-op) | aborts | ✓ | (in-flight) | — | — |

\* Read from cache: if local plaintext cache has the data, served. Otherwise fail with `vault_locked`.

#### Transitional Constraints

- `Unlocking`: writes blocked. Reads from cache only. New unlock attempts queue.
- `Locking`: in-flight writes drain (best-effort within a timeout). Snapshot is forced. Outbound WAL flush flushed. Then keys zeroized.
- `Destroying`: writes rejected immediately. Reads from cache only. Repair scheduler is repurposed for the destruction sweep. Lease released. Anti-entropy paused. Multi-device sync suspended.
- `Destroyed`: terminal. The Vault entity is removed from the engine's vault list. Any cached state is purged. Surviving ciphertext on backends (now keyless) is enumerated in the residual report.

### 6.4 Lease State

```
   ┌─────────┐
   │  Free   │
   └────┬────┘
        │ acquire (CAS write)
        ▼
   ┌─────────┐
   │ Held    │──────► renew → Held
   └────┬────┘
        │ release  /  TTL expire / device crash
        ▼
   ┌─────────┐
   │ Free    │
   └─────────┘

(Lease is advisory: concurrent writes from non-holders are not blocked,
 only their snapshot-coordination preference is.)
```

### 6.5 Chunk Replication State

(Used as a derived signal for repair scheduling and user reporting.)

```
   ┌──────────┐
   │   Full   │  all N shards healthy
   └────┬─────┘
        │ a shard becomes Degraded
        ▼
   ┌──────────┐    ┌────────────┐
   │ Degraded │◄──►│ Recovering │
   └────┬─────┘    └─────┬──────┘
        │ healthy < K    │ all shards Healthy
        ▼                ▼
   ┌──────────┐         back to Full
   │   Lost   │
   └──────────┘
```

---

## 7. CRDT Op Vocabulary (concrete)

Every WAL entry's `op` field is one of the following. See [`RESILIENCE.md`](./RESILIENCE.md) §3.1 and [`DESIGN.md`](./DESIGN.md) §5.2.

```
Op (sum type)
├ LwwSet              { target: Key, value: bytes, previous_value: Option<bytes> }
├ LwwRegister         { target: Key, value: bytes }
├ LwwRegisterIndirect { target: Key, value_hash: BlakeHash,
│                       value_storage_key: LocalKvKey,
│                       value_size_bytes: u32,
│                       previous_value_hash: Option<BlakeHash> }
│                     ← used when value > wal.max_entry_bytes (default 64 KB);
│                       the actual bytes live in metadata/ keyed by value_storage_key
├ OrSetAdd            { target: Key, add_id: u128, value: bytes }
├ OrSetRemove         { target: Key, remove_for_add_ids: list<u128> }
├ CounterInc          { target: Key, delta: i64 }
├ MapPut              { target: Key, map_key: bytes, value: bytes }
├ MapDel              { target: Key, map_key: bytes, remove_for_add_ids: list<u128> }
└ PathMove            { from_path: string, to_path: string, file_id: FileId,
                        linked_remove_id: u128, linked_add_id: u128 }
```

**Resolution rules:**
- `LwwSet` and `LwwRegister`: highest HLC wins; tiebreak by `device_id`. `LwwSet` additionally triggers Shadow demotion when remote `previous_value` ≠ local current value.
- `LwwRegisterIndirect`: same HLC ordering as `LwwRegister`; on apply, the engine ensures `value_storage_key` is resolvable in `metadata/`. If missing on this device (e.g., remote op references a value we don't yet have), record a pending entry and fetch via `vault/`'s WAL+blob replication. Until resolved, the field's effective value is "unresolved indirect"; reads block or return last-known until resolved.
- `OrSetAdd` / `OrSetRemove`: observed-remove semantics; remove only cancels adds it has observed (by `add_id`).
- `CounterInc`: commutative; sum of all increments.
- `MapPut` / `MapDel`: per-key OR-Set semantics.
- `PathMove`: linked OR-Set ops; HLC tiebreak; loser's destination retained in concurrent-rename history for user review.

**Op-size policy:**
- WAL entries MUST NOT exceed `wal.max_entry_bytes` (default 64 KB).
- An L4 service constructing an op whose serialized size would exceed the limit MUST use the `LwwRegisterIndirect` form: write the value to `metadata/` under a content-addressed key, then emit the indirect op. The value blob participates in vault replication via the snapshot's `Shadows`/large-value column family (or its own column family); peers fetch the blob during snapshot pull or anti-entropy.

**Indirect-eligibility policy (AD-1):**

`LwwRegisterIndirect` returns "last-known until resolved" semantics — reads on an unresolved indirect target either block or return a stale value. For most fields this is acceptable. For *security-critical* fields, stale-read semantics could violate invariants (e.g., reading an old `wrapped_keys` after a revocation, or trusting a stale `allowed_devices` set during WAL replay).

The following fields MUST NOT be stored as `LwwRegisterIndirect`:

| Field | Why excluded |
|---|---|
| `File.wrapped_keys` | Revocation correctness — a stale read could grant access to a revoked recipient. (This field is already an OR-Set per recipient, so single-op size is bounded; never needs indirection.) |
| `Vault.identity_chain` | Cold-start trust correctness; chain MUST be fully verifiable from anchor on every load. |
| `Vault.allowed_devices` | WAL-replay authorization correctness; HLC-windowed checks need authoritative current state. |
| `RecoveryManifest.*` (any field) | Cold-start trust anchor; never indirected. The manifest as a whole is a single signed blob. |
| `Vault.snapshot_pointer` | Signed by current epoch; indirection would break signature verification. |
| `LeaseRecord.*` | Lease integrity; signed and CAS-written; indirection breaks atomicity. |

Engines enforcing this MUST surface a build-time or runtime check that ops targeting these fields cannot be rewritten by `sync/` into `LwwRegisterIndirect`. If such an op would naturally exceed `wal.max_entry_bytes`, that's a schema bug — the field should be redesigned as a CRDT collection (OR-Set / OR-Map) so individual operations stay bounded.

For all *other* fields, indirection is allowed when needed.

---

## 8. Data-Flow Primitives

Every diagram in the system reduces to combinations of these primitives. A data flow diagram is a graph whose nodes are components (from §1 / §9) and whose edges are these primitives.

### 8.1 Edge Kinds

| Primitive | Notation | Sync? | Direction |
|---|---|---|---|
| **Request** | `A ──req──► B`  | sync; awaits response | unidirectional |
| **Response** | `B ──resp──► A` | sync | unidirectional |
| **Stream** | `A ══►══► B` (double arrow) | async; framed | unidirectional |
| **Event** | `A ⟶ B` (thin arrow) | async; fire-and-forget | unidirectional, fanned out by L5 |
| **Persist** | `A ──[w]──► Store` | sync | A writes to local KV |
| **Read** | `A ──[r]──► Store` | sync | A reads from local KV |
| **PluginCall** | `A ─[plugin]─► P` | sync; sandboxed for 3rd-party | through Plugin Host |
| **Net** | `A ─[net]─► Backend` | sync via plugin | external |
| **WalAppend** | `A ──[wal]──► WAL` | sync | A appends a WalEntry |
| **WalReplicate** | `WAL ══[net]══► VaultProvider` | async stream | flushes WAL segments |
| **Snapshot** | `Store ══[snap]══► VaultProvider` | async; differential pages | atomic pointer swap |
| **Merge** | `WAL ⊕ WAL → State` | computational | CRDT merge |

### 8.2 Atomic Composite Operations

Reusable bundles of primitives that appear together in many flows.

#### Write a Chunk Shard

```
Core primitive sequence:
  Crypto.derive_chunk_key
  Chunk Engine.encrypt
  Chunk Engine.ec_encode
  Placement.pick_shards_for_chunk           ──► [list of (shard_index, ProviderId)]
  for each (shard_index, provider):
    Plugin Host.invoke(plugin, put, ciphertext)   [PluginCall]
    record handle, register Shadow if needed
  Wait for W = k+1 acks
  Metadata Store.put(...)                         [Persist]
  WAL.append                                      [WalAppend]
  Event Bus.publish(write.quorum_acked)           [Event]
```

#### Read a Chunk

```
  Metadata Store.get(...) → chunk + shards     [Read]
  if Read Cache.has(chunk):
    return Read Cache.get
  Placement: pick K healthiest replicas + H hedges
  for each chosen shard:
    Plugin Host.invoke(plugin, get, handle)    [PluginCall, Stream]
  Take first K to complete; cancel rest
  Chunk Engine.ec_reconstruct
  Crypto.decrypt; verify AEAD
  on verify fail: Repair Scheduler.enqueue (HIGH); log read.repair_triggered
  return plaintext stream
```

#### Snapshot Push

```
  Metadata Store.snapshot_pages_dirty_since(last)   [Read]
  Crypto.encrypt (snapshot key)
  for each VaultProvider:
    Plugin Host.invoke(plugin, put, blob)          [PluginCall]
    verify by peek + hash
    Plugin Host.invoke(plugin, cas_write,
                       snapshot.current pointer)   [PluginCall]
  WAL.truncate up to delta cutoff
  Anti-Entropy Manager.update_local_merkle
  Event Bus.publish(snapshot.completed)
```

#### CRDT Merge from Peer

```
  Vault Manager.fetch_wal_segments(peer_provider, since_seq)  [Stream, Net]
  for each WalEntry:
    verify signature against allowed_devices
    Sync.apply_remote_op(entry)                         [computational]
    if op is LwwSet with previous_value mismatch:
      register Shadow                                   [WalAppend]
  after merge: Anti-Entropy Manager.exchange_with(peer_provider)
```

### 8.3 Diagram Grammar

A data flow diagram is built by composing nodes (from §1) and edges (from §8.1). Every operation in §6 of DESIGN.md can be represented as a sequence of these primitives. New diagrams should be drawn at one of three zoom levels:

- **Zoom 0** (system): nodes are layers L0–L6.
- **Zoom 1** (component): nodes are interfaces from §5.
- **Zoom 2** (operation): nodes are abstract atomic ops from §8.2.

---

## 9. Module Map (recommended)

A suggested mapping from the abstractions to top-level modules. This is *one* valid module decomposition; an implementer could vary it, but the dependency direction (lower to higher) is fixed.

```
core/
├ types/                  L3 — value types from §3, identifiers from §2
├ entities/               L3 — entity records from §4
├ crypto/                 L3 — CryptoContract (§5.2)
├ chunk/                  L3 — ChunkEngineContract (§5.3)
├ placement/              L3 — PlacementContract (§5.4)
├ ec/                     L3 — EC encode/reconstruct
├ bloom/                  L3 — Bloom filter
├ merkle/                 L3 — Merkle tree
├ wal/                    L2 — append-only log + HLC
├ metadata/               L2 — MetadataStoreContract (§5.14)
├ keystore/               L2 — OS secure storage adapter
├ vfs/                    L4 — VfsContract (§5.11)
├ vault/                  L4 — VaultManagerContract (§5.5)
├ lease/                  L4 — Lease state machine
├ sync/                   L4 — SyncContract / CRDT (§5.6)
├ repair/                 L4 — RepairContract (§5.7)
├ antientropy/            L4 — AntiEntropyContract (§5.8)
├ recovery/               L4 — RecoveryContract (§5.9)
├ identity/               L4 — IdentityShareContract (§5.10)
├ share/                  L4 — share creation/import
├ plugin_host/            L1 — PluginHostContract (§5.13), WASM runtime
├ api/                    L5 — ApiServerContract (§5.12)
└ events/                 L5 — event bus

plugins/                  L0 — first-party plugin implementations
└ <plugin_id>/

cli/                      L6 — CLI frontend
gui/                      L6 — native app frontend
fuse/                     L6 — FUSE shim
```

**Dependency rules:**
- `types/`, `entities/` are leaves; everything depends on them.
- L3 primitives depend only on L2 storage and L3 types.
- L4 services compose L3 primitives; never reach into another L4 service.
- L5 (api, events) sits above L4; exposes via interfaces.
- L1 (plugin_host) is the only module that interacts with L0.
- L6 (frontends) speak only the API; never link the engine directly (except for embedded mode).

---

## 10. Cross-Cutting Concerns

### 10.1 Errors

Every fallible operation returns a result whose error variant matches the standard taxonomy (PLUGIN_SDK §9, API §16). Two error spaces:

- **PluginError**: errors from plugin operations (auth, rate-limit, corruption, etc.).
- **CoreError**: errors from core operations (locked vault, format mismatch, etc.).

API maps both to its own envelope.

### 10.2 Events

The event bus is owned by L5 (api). Components publish via a single `publish(event)` interface; subscribers (frontends, internal observers) consume from a filtered stream. Every event is one of the kinds enumerated in API.md §15.2.

### 10.3 Logging

Structured local-only logs. Every component emits a structured record `{level, message, attrs, op?, correlation_id?, error_code?}`. No remote sink. Plugins emit through a host-provided interface; never directly.

### 10.4 Configuration

A typed configuration tree (matching DESIGN.md §11). Every section is a leaf-typed record. Runtime patches via API are validated against the schema before applying.

### 10.5 Identifiers vs. References

Every identifier in §2 is opaque to the layer above. A `ProviderId` from L4's perspective is a black-box string; its origin (UUIDv7) is L1's concern. This rule keeps abstraction boundaries clean.

### 10.6 Determinism Boundaries

Operations declared deterministic (CRDT merge, EC encode/reconstruct, hash, placement-with-fixed-pool) MUST be deterministic. Other operations (network, time, randomness for nonces) are non-deterministic and clearly marked. This boundary matters for property-based testing and for replay-based recovery.

### 10.7 Testing Surfaces

Each interface in §5 is a testing surface. Mock implementations of plugins, vault providers, network behavior, and clocks are required for the test harness. The conformance suite (PLUGIN_SDK §15) tests plugins against `PluginContract`.

---

## 11. From Abstractions to Implementation

The path to executable code:

1. **Types & entities (§2–4)** become the type system foundation. They are the shape of every byte in metadata.
2. **Interfaces (§5)** become the abstract APIs between layers. Implementations are pluggable and mockable.
3. **State machines (§6)** become explicit state types with enumerated transitions, validated at the boundary.
4. **CRDT ops (§7)** become the core merge engine; every WAL entry decodes to one of these.
5. **Data-flow primitives (§8)** become the building blocks of every operation; new operations compose existing primitives rather than inventing new patterns.
6. **Module map (§9)** becomes the actual file-tree layout, with dependency rules enforced by tooling.
7. **Cross-cutting concerns (§10)** become shared infrastructure (errors, events, logs, config).

After this document, drawing a complete data-flow diagram for any operation is mechanical: pick the operation, identify the involved interfaces from §5, expand into primitives from §8.2, render with the notation from §8.1.

---

## 12. Glossary (abstraction-level)

- **Layer**: one of L0..L6, the conceptual decomposition.
- **Interface**: an abstract operation contract, realized as a Rust trait or service object.
- **Identifier**: an opaque value uniquely naming an entity.
- **Entity**: a record with identity, lifecycle, and relationships.
- **Value type**: data without identity.
- **Op**: a single CRDT operation.
- **Primitive (data-flow)**: an atomic edge kind in a data flow diagram.
- **Atomic composite**: a reusable bundle of primitives that appears repeatedly.
- **Zoom**: the level of abstraction at which a diagram is drawn (system / component / operation).
