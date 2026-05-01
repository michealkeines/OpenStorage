# OpenStorage — Architecture & Design

> **Tagline**: *"Your storage. Your providers. Your keys. Orchestrated."*
>
> Open-source, fully client-side tool that orchestrates encrypted personal storage across whatever you bring — cloud accounts, NAS, free-tier services, anything that satisfies the plugin contract. No backend service, no central account. The engine exposes a stable local API; any frontend (CLI, native app, web, mobile, FUSE) consumes it.
>
> **Companion documents:**
> - [`API.md`](./API.md) — local API contract
> - [`PLUGIN_SDK.md`](./PLUGIN_SDK.md) — plugin contract
> - [`RESILIENCE.md`](./RESILIENCE.md) — invariants, edge cases, resolution policies
> - [`THREAT_MODEL.md`](./THREAT_MODEL.md) — adversaries, threats, mitigations

---

# The Core

This section is the canonical statement of what we are building. Every other section of this document, and every companion document, exists in service of what is here. If a future reader can only read one page, this is the page.

## What we are building

A client-side, open-source tool that turns a user's local 15 GB cache (master metadata) plus their 15 GB free cloud Drive (durable backup of that metadata) plus *whatever else they install plugins for* into one encrypted personal disk. The lookup machinery is small and trusted; the bulk-storage tier is provided entirely by plugins implementing a five-operation contract.

**The pitch in one sentence**: 15 GB of metadata gives you 1 TB of usable storage; the bytes live wherever someone has written a plugin to put them.

## Architecture in one picture

```
┌────────────────────────────────────────────────────────────────────┐
│             FRONTENDS  (interchangeable consumers of API)          │
│             CLI │ Native │ Web │ Mobile │ FUSE │ WebDAV            │
└────────────────────────────────┬───────────────────────────────────┘
                                 │ HTTP/2 + WS over UDS / mTLS
┌────────────────────────────────▼───────────────────────────────────┐
│                       ENGINE — API LAYER                           │
└────────────────────────────────┬───────────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────────┐
│                       ENGINE — CORE                                │
│  • Local 15 GB metadata cache (the master)                         │
│  • CRDT WAL with HLC                                               │
│  • Crypto + key custody                                            │
│  • Placement (CRUSH) + EC + Repair + Anti-entropy                  │
│  • Vault Manager (replicates metadata to user's chosen vaults)     │
│  • Plugin Host (in-process + WASM sandbox)                         │
└────────────────────────────────┬───────────────────────────────────┘
                                 │ five-operation contract
┌────────────────────────────────▼───────────────────────────────────┐
│                  PLUGINS — anything that satisfies                 │
│       put / get / peek / delete / health (and CAS for vaults)      │
└────────────────────────────────┬───────────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────────┐
│  BACKENDS — Drive │ OneDrive │ Mega │ NAS │ Telegram │ archive.org │
│             │ Imgur │ Pastebin │ Discord │ Comment threads │ …     │
│             (clean / hostile / future-invented; the core does not  │
│              know or care which species; only the plugin does)     │
└────────────────────────────────────────────────────────────────────┘
```

## The plugin contract — five operations

Every plugin implements:

| Op | Inputs | Outputs |
|---|---|---|
| `put` | payload, optional `replaces_handle`, idempotency key | new handle, `handle_changed`, `prior_handle_state` (overwritten / removed / tombstoned / abandoned / unknown), `quota_reclaimed` |
| `get` | handle, optional range | ciphertext |
| `peek` | handle | exists, size, mtime, etag |
| `delete` | handle | outcome (removed / tombstoned / abandoned / not_supported / not_found), `quota_reclaimed`, `cached_elsewhere_risk` |
| `health` | (none) | state, quota, rate-limit, p95 latency |

Vault-role plugins also implement `list` and `cas_write`.

That is the entire surface a plugin must provide. Everything else is the core's job.

## The ten invariants the core preserves

These hold *regardless of how plugins behave*. A misbehaving plugin (lying capabilities, refusing delete, returning new handles, crashing, vanishing) cannot violate any of these.

| # | Invariant | Mechanism |
|---|---|---|
| **I1** | Confidentiality — backends never see plaintext | Client-side AEAD before any plugin call (§8.2) |
| **I2** | Integrity — tampered ciphertext detected | AEAD tag + chunk hash + signed snapshot pointer (§6.4, §8.4) |
| **I3** | Availability — loss of (N−K) plugins survives | EC + diversity + repair scheduler (§7.2, §7.3, §6.5) |
| **I4** | No silent data loss — losses surfaced per file | Scrub + `chunk.lost` events (§10) |
| **I5** | No silent storage leaks — every placed byte is referenced or shadowed | Shadow registry + `previous_value` demotion (§5.1, §5.2, §6.3.2) |
| **I6** | Eventual consistency across the user's devices | CRDT WAL with HLC + Merkle anti-entropy (§5.2, §6.7, §6.8) |
| **I7** | Deterministic cold start — fresh device + key reproduces state | Signed monotonic snapshot + identity epoch chain (§6.6, §8.4.1) |
| **I8** | Plugin malfeasance is contained — keys, plaintext, credentials safe | WASM sandbox + `signed_fetch` + capability allowlist (`PLUGIN_SDK.md` §7) |
| **I9** | Honest accounting — usable space and orphans truthfully reported | Pool-aware planner + shadow registry + untrusted-quota mode (§7.6, §7.7) |
| **I10** | Quorum durability — committed writes survive (N−W) backend losses | W = k+1 ack at write time + diversity at placement (§6.3, §11.3) |

Resolution policies for every edge case are in [`RESILIENCE.md`](./RESILIENCE.md) §2.

## What this is **not**

- Not a service we operate. There is no server we run, ever.
- Not a marketplace, billing system, or hosted platform.
- Not co-editing software. Sharing exists; concurrent peer co-edit does not.
- Not a guarantee that backends physically delete bytes on demand. Encryption + crypto-shred is the deletion guarantee.
- Not recoverable if the user loses both their key and their recovery materials. By design.
- Not a system that ships hostile-backend plugins in core. Those exist as community plugins; the architecture supports them, the project does not curate them.

## The promise

> *A plugin can behave in any way the contract permits. The core preserves all ten invariants. Plugins implement five operations; the core does everything else.*
>
> *Storage scales as the plugin ecosystem grows. Adding a plugin grows usable storage. Removing one shrinks it predictably. Every byte is either referenced, shadowed, or honestly reported as outside our control.*

That is the entire product. Everything below is detail.

---

## 0. Decision Log

| # | Topic | Decision | Why |
|---|---|---|---|
| 1 | Backend model | No backend service; engine on user's device or self-host | Project mandate |
| 2 | Architecture shape | Single-baseline design; engine + frontends; stable local API | Frontend-agnostic |
| 3 | Metadata vault | Pluggable, replicated across ≥1 user-chosen providers | No single-provider dependency |
| 4 | Backend plugins (red) | Removed from core; third-party WASM-sandboxed only | Legal isolation |
| 5 | Redundancy default | Erasure coding (Reed–Solomon, 4-of-7); replication for tiny files | Lower overhead, better resilience |
| 6 | Default AEAD | ChaCha20-Poly1305; AES-256-GCM with hardware accel | Mobile-friendly |
| 7 | KDF | Profile-driven Argon2id with honest level reporting | No silent degradation |
| 8 | Asymmetric crypto | Ed25519 + ML-KEM-768 baseline | Sharing is baseline |
| 9 | Chunking | Fixed-size default (4 MB); CDC opt-in with padding+packing | Honest about dedup, defends keyed-CDC attack |
| 10 | Multi-device | CRDT-encoded WAL with HLC from day one | No painful migration later |
| 11 | Recovery | Passphrase + recovery file + Shamir + hardware key, user-chosen | First-class story |
| 12 | UX surfaces | Native app primary; CLI / web / mobile / FUSE all via API | Frontend-agnostic |
| 13 | Plugin model | First-party in-process; third-party WASM-sandboxed | Safe extension |
| 14 | Snapshot strategy | Differential page-diff + WAL stream + periodic full | Bandwidth-aware |
| 15 | Vault destruction | Crypto-shred + best-effort delete + residual report | Privacy honesty |
| 16 | Telemetry / central | None (no-backend rule) | Project mandate |
| 17 | Diversity rule | Trust-correlation graph between providers | Microsoft owns multiple services |
| 18 | Pricing | Open source, donation-funded, BYO-providers | Sustainability |
| 19 | WAL entry shape | Causal envelope (HLC + op kind expressible as CRDT) | Multi-device merging from day one |
| 20 | FILE schema | `wrapped_keys` is a list `[{recipient_id, wrapped_key}]` | Sharing without migration |
| 21 | Key purposes | Enumerated and reserved at HKDF info parameter | Prevents derivation collisions |
| 22 | Snapshot page payloads | Self-describing opaque envelopes (CBOR with version tag) | Format evolves cleanly |
| **23** | **Write durability** | **Quorum acks: write commits when `W = k+1` shards ack; rest fan out async** | **Standard durability/latency trade (Cassandra, Storj)** |
| **24** | **Read latency** | **Hedged requests: fetch `K + H` shards in parallel after p95-threshold** | **Tail-at-Scale (Dean & Barroso) — proven 99.9p reduction** |
| **25** | **Read repair** | **Inline repair on verify failure during a read** | **Cassandra/Dynamo standard; faster than scrub-only** |
| **26** | **Anti-entropy** | **Merkle tree (depth 15) exchange between vault replicas** | **Cassandra/Riak/Dynamo standard for efficient reconciliation** |
| **27** | **Repair scheduling** | **Priority queue keyed on (redundancy gap, recency, access frequency)** | **Ceph standard; data closer to floor repaired first** |
| **28** | **Tiny-file optimization** | **Files ≤ 4 KB inlined into the FILE record (single AEAD blob)** | **SeaweedFS/object-store standard; metadata cost win** |
| **29** | **Existence checks** | **Per-vault Bloom filter over chunk hashes** | **Standard dedup acceleration** |
| **30** | **CDC attack defense** | **CDC implies mandatory compression + padding + chunk packing** | **Mitigates Truong 2024 algebraic attack on Borg/Restic-style CDC** |

---

## 1. Vision & Scope

### 1.1 The Product

A user installs OpenStorage. They bring their own cloud accounts (Drive, OneDrive, Mega, Storj, S3-compatible bucket, NAS at home). They pick a passphrase and a recovery strategy. They optionally exchange identity blobs with people they want to share with. The engine encrypts everything client-side, splits files into erasure-coded shards, places those shards across the user's providers with redundancy and integrity, and serves a stable local API any frontend can drive.

The pitch is **orchestration**, not free storage.

### 1.2 Hard Constraints

- **No backend service.** No central infrastructure. Ever.
- **Open source.** Permissive license, reproducible builds.
- **Client-side only.** All code runs on the user's device or self-hosted daemon they own.
- **Encryption is mandatory and client-side.** Backends never see plaintext.
- **Backends are reached via plugins.** No service we operate sits in the path.
- **API is the contract.** Frontends and engine evolve independently behind a stable API.

### 1.3 Out of Scope

- Real-time multi-user collaboration.
- ToS-violating drivers in the core.
- Storing illegal content.
- Replacing audited cryptographic primitives.
- Plausible-deniability vaults (future).
- Default cover-traffic mode (opt-in only).

### 1.4 Target Scale

| Metric | Realistic | Headroom |
|---|---|---|
| Per-vault metadata | ~10 GB | up to 15 GB |
| Per-vault user data | ~1 TB | ~5 TB with compression / large chunks |
| Chunks per vault | ~50 M | bounded by metadata budget |
| Backends per vault | unbounded; expected 3–10 | |
| Metadata vaults | 1–3 (replicated) | |
| Devices per vault | unbounded; CRDT-merged | |

---

## 2. Design Principles

1. **Local-first authority.** Device is master. Cloud is durable backup.
2. **No backend, ever.** No server we operate.
3. **The user owns the key.** Recovery is user-configurable and explicit.
4. **Pluggable everything.** Backends, vaults, recovery sources.
5. **Honest about backend reality.** Failures are steady state, not exception.
6. **API as the contract.** Frontends and engine decoupled.
7. **CRDT-first metadata.** Multi-device merge baseline.
8. **Identity-aware.** Sharing baseline; per-recipient key wraps.
9. **Forward-compatible formats.** Versioned schemas; opaque envelopes.
10. **Adopt established techniques.** Quorum acks, hedged reads, Merkle anti-entropy, priority repair — all proven in production systems.
11. **Sustainable open source.** No business model that requires servers.

---

## 3. System Architecture

### 3.1 Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                        FRONTEND LAYER                            │
│   CLI │ Native app │ Local web app │ Mobile │ FUSE │ WebDAV      │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTP/2 + WS over UDS / mTLS
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                       ENGINE — API LAYER                         │
│   Auth │ Routing │ Streaming │ Events │ Capability negotiation   │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│                       ENGINE — CORE                              │
│  VFS │ Metadata │ Crypto │ Chunk Engine │ Placement              │
│  Vault Mgr │ Lease │ Sync (CRDT) │ Recovery │ Identity           │
│  Share Mgr │ Plugin Host │ Repair Scheduler │ Anti-Entropy       │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                        PROVIDER PLUGINS                          │
│   Drive │ OneDrive │ Mega │ S3-compat │ Storj │ NAS │ [3rd-party]│
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Storage Tiers

```
Tier 1: LOCAL DEVICE
  • Master metadata cache (LSM KV, ~10 GB)
  • Bloom filter over chunk hashes
  • Chunk staging
  • Encrypted plaintext read cache
  • WAL (CRDT-shaped causal entries)
  • Encryption keys (in OS secure storage)

Tier 2: METADATA VAULT(S) — pluggable, replicated, Merkle-reconciled
  • Encrypted snapshots
  • WAL segments
  • Lease record
  • Recovery manifest
  • Merkle tree summary (for anti-entropy)

Tier 3: CHUNK BACKENDS — pluggable, erasure-coded
  • Encrypted shards (4-of-7 by default)
  • Diverse across trust-correlation groups
```

### 3.3 Deployment Topologies

```
─── Single-device app ──────────────────────────────────────────
   [User's laptop] — native app + engine — plugins → backends

─── Self-hosted daemon ─────────────────────────────────────────
   [User's NAS / server] — engine daemon — plugins → backends
        ▲ private net (Tailscale / WireGuard / LAN, mTLS)
   [Laptop] [Phone] [Tablet] — thin frontends consume API

─── Embedded library ───────────────────────────────────────────
   [Frontend app] — engine library linked in-process
```

Same engine, same API, same plugins everywhere.

---

## 4. Component Breakdown

### 4.1 Component Map

```
┌───────────────────────────── ENGINE ─────────────────────────────────┐
│                                                                      │
│  ┌──────────────────────── API LAYER ───────────────────────────┐    │
│  │  Auth │ Routing │ Streaming │ Events │ Capabilities │ TLS/UDS│    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                 │                                    │
│  ┌──────────────────────────────▼───────────────────────────────┐    │
│  │                       VIRTUAL FILESYSTEM                     │    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                 │                                    │
│  ┌──────────────────────────────▼───────────────────────────────┐    │
│  │                       METADATA STORE                         │    │
│  │  Namespace │ Files │ Chunks │ Shards │ WAL (HLC, CRDT ops)   │    │
│  │  Bloom filter │ Merkle tree │ Lease │ Manifests              │    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                 │                                    │
│  ┌────────────┬──────────┬──────┼─────────┬──────────┬─────────┐     │
│  ▼            ▼          ▼      ▼         ▼          ▼         ▼     │
│ ┌──────┐  ┌────────┐ ┌────────┐┌────────┐┌──────────┐┌──────────┐    │
│ │Crypto│  │ Chunk  │ │ Sync   ││Identity││ Repair   ││  Anti-   │    │
│ │+Keys │  │ Engine │ │ Mgr    ││ +Share ││Scheduler ││ Entropy  │    │
│ │      │  │ +Hedge │ │ (CRDT) ││  Mgr   ││(priority)││ (Merkle) │    │
│ │      │  │ +Repair│ │        ││        ││          ││          │    │
│ └──┬───┘  └───┬────┘ └───┬────┘└────┬───┘└─────┬────┘└─────┬────┘    │
│    │          │          │          │           │          │         │
│    │          ▼          │          │           │          │         │
│    │  ┌──────────────┐   │          │           │          │         │
│    │  │  Placement   │   │          │           │          │         │
│    │  │  Engine      │   │          │           │          │         │
│    │  │ (caps,       │   │          │           │          │         │
│    │  │  diversity,  │   │          │           │          │         │
│    │  │  health,     │   │          │           │          │         │
│    │  │  quotas)     │   │          │           │          │         │
│    │  └──────┬───────┘   │          │           │          │         │
│    │         │           │          │           │          │         │
│    ▼         ▼           ▼          │           │          │         │
│   ┌──────────────────────────────────────────────────────┐           │
│   │             PLUGIN HOST                              │           │
│   │   In-process: Drive/OneDrive/Mega/Storj/S3/NAS       │           │
│   │   WASM-sandboxed: 3rd-party plugins                  │           │
│   └──────────────────────────┬───────────────────────────┘           │
│                              │                                       │
│  ┌───────────────────────────▼───────────────────────────────────┐   │
│  │   VAULT MANAGER (replicated metadata across ≥1 vaults)        │   │
│  │   LEASE MANAGER (advisory primary-writer hint)                │   │
│  │   RECOVERY MANAGER (passphrase / file / Shamir / hardware)    │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.2 New / Updated Component Responsibilities

#### 4.2.1 Chunk Engine (updated)
- Splits, hashes, encrypts shards.
- **Streams reads with hedged-request scheduling** (see §6.4).
- **Issues read repair on detected verify failures** (see §6.5).
- Inlines tiny files instead of chunking (see §6.3.1).
- Consults the **Bloom filter** to short-circuit existence checks.

#### 4.2.2 Repair Scheduler (NEW component)
- Maintains a priority queue of degraded chunks.
- Score = `(replicas_floor - current_replicas) × W_floor + recency_bonus + access_bonus`.
- Bounded worker pool drains the queue, calls placement engine for fresh placement.
- Sources of work: scrubber, read-repair detection, plugin health-changed events.

#### 4.2.3 Anti-Entropy Manager (NEW component)
- Maintains a logical Merkle tree (depth 15, 32K leaves) over the metadata snapshot pages.
- Periodically exchanges root hashes with each configured vault provider.
- On root mismatch, walks down to identify divergent ranges, pulls only differing pages, applies via CRDT WAL replay.

#### 4.2.4 Sync Manager (CRDT) — clarified
- Handles **inter-device** reconciliation via WAL exchange.
- Distinct from Anti-Entropy Manager which handles **inter-vault** reconciliation.
- Both use the same underlying CRDT op semantics; they differ in transport (WAL stream vs. Merkle-guided pull).

---

## 5. Data Model

### 5.1 Logical Entities

```
┌────────────────────────────────┐
│            VAULT               │
│ ─────────────────────────────  │
│ vault_id                       │
│ format_version                 │
│ owner_identity_pubkey          │
│ created_at                     │
│ aead_suite                     │
│ kdf_params                     │
│ recovery_manifest_ref          │
│ snapshot_pointer (signed,      │
│   monotonic version counter)   │
│ lease_path                     │
│ allowed_devices[]              │
│ merkle_root_pointer            │  ← anti-entropy root
└───────────────┬────────────────┘
                │ N
┌───────────────▼────────────────┐
│            FILE                │
│ ─────────────────────────────  │
│ file_id (UUIDv7)               │
│ path                           │
│ size_bytes                     │
│ created_at, modified_at        │
│ permissions                    │
│ content_type                   │
│ inline_payload (nullable):     │  ← if size ≤ inline_threshold,
│   { aead_blob, nonce, tag }    │     entire file lives here
│ chunk_list (ordered hashes)    │  ← otherwise normal chunk list
│ wrapped_keys[]:                │
│   [{ recipient_id, wrapped,    │
│      wrap_scheme, wrapped_at }]│
│ acl[] (per-recipient perms)    │
└───────────────┬────────────────┘
                │ N
┌───────────────▼────────────────┐
│           CHUNK                │
│ ─────────────────────────────  │
│ chunk_hash (BLAKE3-256)        │
│ plaintext_length               │
│ ec_scheme (k_of_n)             │
│ shard_list (ordered shards)    │
│ refcount                       │
│ replication_state              │  ← FULL / DEGRADED / RECOVERING
│ last_scrubbed_at               │
│ access_count_window            │  ← drives repair priority
└───────────────┬────────────────┘
                │ N
┌───────────────▼────────────────┐
│           SHARD                │
│ ─────────────────────────────  │
│ shard_id                       │
│ shard_index (for EC)           │
│ encryption_nonce               │
│ encryption_tag                 │
│ ciphertext_length              │
│ driver_id                      │
│ native_handle (opaque)         │
│ stored_at                      │
│ last_verified_at               │
│ health_score                   │
│ ack_state                      │  ← ACKED / IN_FLIGHT / FAILED
└────────────────────────────────┘

┌────────────────────────────────┐
│         SHADOW SHARD           │  ← ciphertext we no longer reference
│ ─────────────────────────────  │     but cannot reclaim from backend
│ shadow_id                      │
│ original_chunk_hash            │
│ driver_id                      │
│ native_handle                  │
│ ciphertext_length              │
│ abandoned_at                   │
│ reason                         │  ← update_replaced /
│                                │     repair_replaced /
│                                │     deletion_orphaned
│ cached_elsewhere_risk          │  ← low / medium / high
│ counts_against_quota           │  ← bool, from plugin report
│ tombstone_clears_at            │  ← optional; if backend tombstoned
└────────────────────────────────┘

┌────────────────────────────────┐    ┌────────────────────────────────┐
│        VAULT PROVIDER          │    │        CHUNK BACKEND           │
│ ─────────────────────────────  │    │ ─────────────────────────────  │
│ provider_id, kind, label       │    │ provider_id, kind, label       │
│ priority                       │    │ capabilities                   │
│ credentials_handle             │    │ trust_correlation_group        │
│ last_synced_at                 │    │ legal_class                    │
│ merkle_root_etag               │  ← │ credentials_handle             │
└────────────────────────────────┘    │ quota_total, quota_used        │
                                      │ rate_limit_state               │
                                      │ health_score                   │
                                      │ p95_read_latency_ms            │  ← drives hedge threshold
                                      └────────────────────────────────┘

┌────────────────────────────────┐    ┌────────────────────────────────┐
│         IDENTITY               │    │           PEER                 │
│ ─────────────────────────────  │    │ ─────────────────────────────  │
│ identity_id (own)              │    │ peer_id                        │
│ sign_pubkey (Ed25519)          │    │ sign_pubkey                    │
│ kem_pubkey (ML-KEM-768)        │    │ kem_pubkey                     │
│ created_at, rotated_at         │    │ label, verified, added_at      │
│ wrapped_privkeys (under MK)    │    │                                │
└────────────────────────────────┘    └────────────────────────────────┘

┌────────────────────────────────┐    ┌────────────────────────────────┐
│            SHARE               │    │       RECOVERY MANIFEST        │
│ ─────────────────────────────  │    │ ─────────────────────────────  │
│ share_id, scope, scope_ref     │    │ manifest_id, format_version    │
│ recipient_peer_id              │    │ recovery_modes[]               │
│ permissions[]                  │    │ wrapped_master_keys[]          │
│ wrapped_keys_ref               │    │ identity_pubkey_fingerprint    │
│ created_at, expires_at         │    │ updated_at                     │
│ revoked_at (nullable)          │    │                                │
└────────────────────────────────┘    └────────────────────────────────┘

┌────────────────────────────────┐    ┌────────────────────────────────┐
│         LEASE RECORD           │    │           DEVICE               │
│ ─────────────────────────────  │    │ ─────────────────────────────  │
│ holder_device_id               │    │ device_id, device_label        │
│ acquired_at, expires_at        │    │ first_seen_at, last_seen_at    │
│ renewal_count                  │    │ device_pubkey (Ed25519)        │
│ holder_signature (Ed25519)     │    │ revoked_at (nullable)          │
└────────────────────────────────┘    └────────────────────────────────┘
```

### 5.2 WAL Entry Shape

```
WAL_ENTRY {
  seq             : monotonic local sequence
  hlc             : hybrid logical clock timestamp
  device_id       : originating device
  op_kind         : enum (see table below)
  target          : key path within metadata
  payload         : op-specific bytes (CBOR)
  previous_value  : for handle-targeting LWW_SET only —
                    the value the writer is replacing,
                    used to detect concurrent-update
                    demotion during CRDT merge
  signature       : Ed25519 over the above (per-device key)
}
```

#### Op Kind Vocabulary

| Op kind | Semantics | Used for |
|---|---|---|
| `LWW_SET` | Last-writer-wins register; carries `previous_value` for handle/driver fields | Scalar fields whose old value represents placed ciphertext |
| `LWW_REGISTER` | LWW without previous_value | Scalar fields with no shadow concern (mode, content_type, mtime) |
| `OR_SET_ADD` | Observed-remove set add (carries `add_id`) | Lists: recipients, devices, shadows, peers, shares |
| `OR_SET_REMOVE` | Observed-remove set remove (references `add_id`) | Revocation, removal from lists |
| `COUNTER_INC` | Monotonic counter increment | Refcount, access count |
| `MAP_PUT` / `MAP_DEL` | Sharded map update | Per-driver state |

> **Namespace note.** The filesystem-shaped API (paths, `move`, `dirs`) is a *projection* of a flat FILE-record set, not a stored tree. `path` is a regular `LWW_REGISTER` field on the FILE record (keyed by stable `file_id`). Renames and moves are LWW writes to that field; directory listings are computed by prefix-grouping at read time. There is no `PATH_MOVE` composite op. See §5.8 ("Namespace Projection & Merge") for the projection rules and §6.13 for the read-time listing algorithm.
>
> This keeps the API and flows in §6 unchanged while making multi-device merge deterministic without a tree CRDT.

All op kinds are commutative + associative + idempotent → multi-device merge is deterministic. See [`RESILIENCE.md`](./RESILIENCE.md) §3.1 for the full vocabulary and §2.B for resolution policies under concurrency.

#### Concurrent Handle-Update Resolution (Case 6)

When merging a remote `LWW_SET` op whose `previous_value` does NOT match the local current value (i.e., we have a different handle that we wrote ourselves), the local handle is **demoted** to a shadow:

```
on apply remote LWW_SET(target, value=H_remote, previous_value=H_remote_prev):
  if local_current_value(target) == H_remote_prev:
    standard LWW: set target = H_remote
  else:
    # concurrent update — both devices wrote, we're losing
    demoted = local_current_value(target)
    set target = H_remote (HLC ordering already determined we lose)
    emit OR_SET_ADD(shadows, {
      handle: demoted,
      reason: concurrent_update_demoted,
      …
    })
```

This invariant-preserving rule eliminates the silent-orphan storage leak that would otherwise occur when two devices update the same chunk concurrently.

### 5.3 Snapshot Page Format

```
SNAPSHOT_PAGE {
  page_id       : stable identifier
  page_version  : monotonic per page
  payload_kind  : "file_records" | "chunk_records" | "namespace" | …
  payload_codec : "cbor.v1" | …
  payload_bytes : opaque
}
```

The Anti-Entropy Manager builds the Merkle tree from `(page_id, page_version)` hashes — never inspects payload. Format evolution is decoupled from the snapshot layer.

### 5.4 Bloom Filter

A per-vault Bloom filter over chunk hashes:

| Parameter | Default |
|---|---|
| Target false-positive rate | 1% |
| Hash count | 7 |
| Sized for | 50M chunks |
| Approx size | ~60 MB |

Persisted alongside metadata, refreshed on every snapshot. Used for:
- Dedup checks (does this content already exist? — definitive negative; possible positive triggers metadata lookup).
- Fast existence verification before scrub.
- Pre-write checks before fanning to plugins.

### 5.5 Merkle Tree (anti-entropy)

```
                       root hash
                     /           \
              h_left              h_right
            /        \         /          \
         h_LL    h_LR    h_RL      h_RR        ← intermediate (depth 15)
         / \     / \      / \       / \
        ...                                     ← 32,768 leaves
        page_id × page_version → BLAKE3 hash
```

- Depth 15 → 32,768 leaves (matches Cassandra's standard).
- Each leaf is a hash of `(page_id, page_version, payload_hash)` for one snapshot page bucket.
- Tree built incrementally on every snapshot delta.
- Root + path needed for divergence walk transmitted between vaults — small (a few KB).

### 5.6 Capability Flags

See `PLUGIN_SDK.md` §6.

### 5.7 Shard Lifecycle

```
        ┌──────────┐
        │  STAGED  │
        └────┬─────┘
             │ placement engine assigns
             ▼
        ┌──────────┐
        │ PLACING  │
        └────┬─────┘
             │ ack from driver
             ▼
        ┌──────────┐
   ┌───►│  HEALTHY │◄───── repair completes
   │    └────┬─────┘
   │         │ verify fail / scrub fail / read-repair detection
   │         ▼
   │    ┌──────────┐
   │    │ DEGRADED │── enqueued in repair scheduler
   │    └────┬─────┘
   │         │ repair places fresh shard
   └─────────┘
             │
             │ EC threshold breached (chunk-level)
             ▼
        ┌──────────┐
        │   LOST   │  (chunk-level alert; user notified per file)
        └──────────┘
```

### 5.8 Namespace Projection & Merge

The engine exposes a filesystem-shaped API (§ in `API.md` §8) — paths, `move`, `dirs`. Internally, it does **not** store a tree. It stores a flat collection of FILE records keyed by stable `file_id` (UUIDv7), each carrying a `path` field. The "tree" is computed at read time. This makes every namespace operation reduce to a CRDT primitive that already exists in §5.2.

#### 5.8.1 Storage model

```
namespace = OR_SET<FILE_RECORD>
  where each FILE_RECORD has:
    file_id : UUIDv7         (stable identity — never changes for the life of the file)
    path    : LWW_REGISTER   (the user-visible label; changes on rename/move)
    …all other FILE fields…

dirs = OR_SET<DIR_RECORD>
  where each DIR_RECORD has:
    dir_id  : UUIDv7
    path    : LWW_REGISTER
  (only used to persist *empty* directories — implicit dirs need no record)
```

There are no parent/child pointers. There is no "directory entry list." The relationship between a file and its directory is implied by string-prefix on `path`.

#### 5.8.2 Operation → CRDT mapping

| API operation | CRDT op(s) |
|---|---|
| `PUT /files/{path}` (new) | `OR_SET_ADD(namespace, FILE{file_id, path, …})` |
| `PUT /files/{path}` (existing — chunk_list update) | `LWW_SET` on chunk_list of the matching FILE record |
| `POST /files/{path}/move { to }` | `LWW_REGISTER` on `path` of the matching FILE record |
| `POST /files/{path}/copy { to }` | new `file_id`; `OR_SET_ADD`; chunk_list shared (refcount++) |
| `DELETE /files/{path}` | `OR_SET_REMOVE` on the matching FILE record |
| `GET /dirs/{path}` | read-side prefix scan over namespace (see §6.13) |
| `POST /dirs/{path}` | `OR_SET_ADD(dirs, DIR{dir_id, path})` |
| `DELETE /dirs/{path}` (recursive) | batched `OR_SET_REMOVE` on every FILE/DIR with matching prefix at op HLC |

`PATH_MOVE` is removed from the op vocabulary — it was a composite for a tree we no longer claim to have.

#### 5.8.3 Merge rules

**Rule N1 — `path` is `LWW_REGISTER`.** Concurrent renames of the same `file_id` are resolved by HLC. Loser's path value is overwritten. The file's content (chunk_list, AEAD blob, wrapped_keys) is unaffected.

**Rule N2 — Same-path collision produces a deterministic conflict copy.** If, after merge, two distinct `file_id`s have identical `path` values, the LWW-loser's *rendered* path is:

```
  {original_path}.conflict-{loser_hlc}-{first_8_chars_of_loser_file_id}
```

The conflict path is a render-time projection — the stored `path` field is unchanged. Every device computes the identical conflict path because HLC and file_id are deterministic. The loser remains accessible via the conflict path until the user renames or deletes it; resolving the conflict path with `POST /files/{conflict_path}/move` updates the stored `path` field as a normal rename, and the conflict suffix disappears.

**Rule N3 — Implicit directories.** A directory `D` appears in `GET /dirs/{parent}` if either:
- any FILE record exists whose `path` starts with `{D}/`, OR
- a DIR record exists with `path == D`.

A FILE record whose path implies a directory whose explicit DIR record was tombstoned **resurrects** the directory (the file's existence wins over the dir's explicit deletion). This handles "device A moved file into /a/b; device B did rmdir /a/b concurrently" — the move wins; the dir is rendered.

**Rule N4 — Recursive delete is per-file, scoped to op HLC.** `DELETE /dirs/{path}` (recursive) expands at op time to a batched `OR_SET_REMOVE` over every FILE/DIR record whose `path` starts with `{path}/` *as observed at the originating device's HLC*. Files added concurrently (causally independent of the recursive delete) are not removed by it; they survive at their declared path and resurrect the directory under Rule N3.

#### 5.8.4 Properties this preserves

- **Convergence**: all merge rules are functions of CRDT field values + HLC + stable file_id. Every device computes the same projection.
- **No silent data loss**: same-path collision produces a conflict copy (visible, addressable), not silent overwrite. Concurrent rename produces one rendered name per file (no file lost).
- **No tree-invariant violations possible at storage layer**: there are no tree invariants stored; orphans, cycles, and parentless-children cannot exist because parents are not pointers.
- **API stability**: every flow in §6 keeps its current shape. Frontends (FUSE, app, CLI) see the same surface.

The cost is a single user-visible artifact: occasional `*.conflict-...` files when two devices write to the same path while both offline. This is the same trade-off accepted by Dropbox, iCloud, Google Drive, Syncthing.

---

## 6. Operations & Data Flows

### 6.1 Lease Acquisition (advisory)

Engine reads lease file from vault. If expired or absent, CAS-writes its own. CRDT WAL allows concurrent writes from multiple devices regardless of lease — the lease is a snapshot-coordination hint, not exclusion.

### 6.2 Vault Unlock

User → API (POST unlock) → Recovery Mgr derives MK → Crypto Mgr loads keys → Vault Mgr fetches latest snapshot from freshest replica → metadata loaded → emit `vault.unlocked` event.

### 6.3 Write Flow with Quorum Acks

```
Frontend     API      VFS    Crypto    Chunk    EC        Placement   Plugin Host  Backends
                                       Engine   Encoder   Engine
   │          │       │       │         │        │          │             │           │
   │ PUT      │       │       │         │        │          │             │           │
   ├─────────►│       │       │         │        │          │             │           │
   │          │ open  │       │         │        │          │             │           │
   │          ├──────►│       │         │        │          │             │           │
   │          │       │ size? │         │        │          │             │           │
   │          │       ├───────┐         │        │          │             │           │
   │          │       │ ≤ inline_threshold ─── inline path (§6.3.1) ───────────────────│
   │          │       │       │         │        │          │             │           │
   │          │       │ chunk path:     │        │          │             │           │
   │          │       │ split chunk     │        │          │             │           │
   │          │       ├────────────────►│        │          │             │           │
   │          │       │ derive chunk key│        │          │             │           │
   │          │       │       ├────────►│        │          │             │           │
   │          │       │       │ encrypt │        │          │             │           │
   │          │       │       │ ciphertext       │          │             │           │
   │          │       │       ├─────────────────►│          │             │           │
   │          │       │       │         │ EC into N shards   │            │           │
   │          │       │       │         ├───────────────────►│            │           │
   │          │       │       │         │        │ for each shard:        │           │
   │          │       │       │         │        │ select driver matching │           │
   │          │       │       │         │        │ caps, trust groups,    │           │
   │          │       │       │         │        │ health, quota          │           │
   │          │       │       │         │        ├──────────────────────►│            │
   │          │       │       │         │        │          │ put         │           │
   │          │       │       │         │        │          ├────────────►│           │
   │          │       │       │         │        │          │             │── async ──►│
   │          │       │       │         │        │          │             │            │
   │          │       │       │         │        │ wait for W = k+1 acks  │            │
   │          │       │       │         │        │ (quorum durability)    │            │
   │          │       │       │         │        │◄───────────────────────┤            │
   │          │       │ commit metadata + WAL append                       │           │
   │          │       │ chunk replication_state = DEGRADED until N acks    │           │
   │          │       │       │         │        │          │             │            │
   │          │ progress event (WS)     │        │          │             │            │
   │ events◄──┼─────────────────────────┼────────┼──────────┼─────────────┤            │
   │          │ ack    │       │         │        │          │             │           │
   │ 201 ◄────┤        │       │         │        │          │             │           │
   │          │                                                                        │
   │          │ background: remaining (N − W) shards complete; chunk → FULL            │
   │          │ background: WAL streamed to vault providers                            │
```

**Quorum semantics**:
- Default `W = k + 1` (one above EC reconstruction floor).
- Configurable per vault and per redundancy class.
- Write is *durable* once W acks land; it transitions to *fully replicated* when all N land.
- A failed ack from any shard re-routes to a fresh driver; doesn't fail the write as long as W is met.

#### 6.3.2 Update vs. Fresh Put — handling the enriched `PutResult`

When the engine is *updating* an existing chunk (e.g., user edits a file and a chunk's content changes), it calls `put(payload, hint={replaces_handle: old_handle, …})` on each shard's plugin. The plugin returns a `PutResult` (see `PLUGIN_SDK.md` §5.2) that the engine interprets as follows:

| `prior_handle_state` from plugin | `handle_changed` | Engine action |
|---|---|---|
| `overwritten` | false | Update shard's `last_verified_at`. No new metadata records. |
| `removed` | true | Replace shard's `native_handle` with new handle. Old object physically gone — no shadow needed. |
| `tombstoned` | true | Replace handle. Register `SHADOW SHARD` with `reason=update_replaced` and `tombstone_clears_at`; engine schedules a follow-up peek to confirm clearance, then removes the shadow. |
| `abandoned` | true | Replace handle. Register `SHADOW SHARD` with `reason=update_replaced` and `cached_elsewhere_risk` from plugin. Shadow persists until vault destruction. |
| `unknown` | true | Replace handle. Register `SHADOW SHARD` with `reason=update_replaced`, treat as `abandoned` for accounting, schedule background `peek` to refine status. |

Only `overwritten` results in zero metadata growth. Every other outcome creates a shadow shard the engine must remember for **quota accounting** and **vault-destruction reporting** — even though the shadow is never fetched, never repaired, and never trusted, because it exists on a backend that didn't fully cooperate. Crypto-shred at vault destruction is what makes shadow ciphertext irrecoverable; the bytes can't leak (the key is gone) but quota costs are real until the backend (if ever) reclaims.

The same logic applies on **repair-replacement** (an old shard is being relocated): if the *old* plugin can't delete, the repair flow registers a shadow with `reason=repair_replaced`. On **straight delete** (chunk refcount drops to zero): the GC path interprets `delete()`'s `outcome` field — `removed` clears the shard record outright, while `tombstoned` / `abandoned` / `unknown` register shadows with `reason=deletion_orphaned`.

#### 6.3.1 Tiny-File Inline Path

```
If file_size ≤ inline_threshold (default 4 KB):
  derive file key
  encrypt entire payload as a single AEAD blob with random nonce
  store { aead_blob, nonce, tag } directly in the FILE record's inline_payload
  no chunk records, no shards, no plugin calls

Saves: ~6 metadata records + N plugin RTTs per tiny file.
```

### 6.4 Read Flow with Hedged Requests

```
Frontend    API     VFS    Metadata    Read     Plugin Host   Backends   EC      Decrypt
                           Store       Cache                             Combiner
   │         │      │         │          │           │          │          │         │
   │ GET     │      │         │          │           │          │          │         │
   ├────────►│      │         │          │           │          │          │         │
   │         │ open │         │          │           │          │          │         │
   │         ├─────►│         │          │           │          │          │         │
   │         │      │ resolve │          │           │          │          │         │
   │         │      ├────────►│          │           │          │          │         │
   │         │      │ INLINE? │          │           │          │          │         │
   │         │      │ yes → decrypt inline → stream → done                 │         │
   │         │      │ no  → chunk_list returned                            │         │
   │         │      │◄────────┤          │           │          │          │         │
   │         │      │                                                                 │
   │         │      │ for each chunk:                                                 │
   │         │      │   cache hit?                                                    │
   │         │      ├──────────────────────►│        │          │          │         │
   │         │      │   miss → fetch shards                                            │
   │         │      │                                                                 │
   │         │      │   plan: K shards required for EC reconstruction                 │
   │         │      │   fire K + H concurrent get() to healthiest replicas            │
   │         │      │   (H = hedge_count, default 2)                                  │
   │         │      ├───────────────────────────────►│          │          │         │
   │         │      │                                │ get()    │          │         │
   │         │      │                                ├─────────►│          │         │
   │         │      │                                │          │── async ►│         │
   │         │      │                                │          │ ciphertxt│         │
   │         │      │                                │ stream   │          │         │
   │         │      │                                │◄─────────┤          │         │
   │         │      │                                │          │          │         │
   │         │      │   if any shard takes > p95_threshold ms:                        │
   │         │      │     fire +1 hedge to next-healthiest replica                    │
   │         │      │                                                                 │
   │         │      │   first K complete → cancel rest                                │
   │         │      ├──────────────────────────────────────────►│         │          │
   │         │      │                                            │ EC      │         │
   │         │      │                                            │ reconstruct        │
   │         │      │                                            │◄────────┤         │
   │         │      │   verify each shard's AEAD tag             │         │         │
   │         │      │   on ANY tag failure → see §6.5 read-repair                     │
   │         │      ├────────────────────────────────────────────────────────────────►│
   │         │      │                                                                 │
   │ stream ◄┼──────┤ decrypted plaintext streams to frontend                         │
```

**Hedge semantics**:
- For EC k-of-n, fire `K + H` initial fetches in parallel.
- After `hedge_after_ms` (default = max of 250 ms or rolling p95 of recent reads), fire 1 additional hedge per straggler.
- Take the first K to complete; cancel rest.
- Per Dean & Barroso: in similar workloads this reduces 99.9p latency dramatically with ~2–5% extra requests.

**Per-shard fault localization** (Invariant I2):
- Each shard's AEAD tag is verified independently *before* EC decode. The AAD is `chunk_hash || shard_index` (§8.2), so a shard that is bit-rotted, substituted from a different chunk, substituted from a different slot, or returned by a hostile plugin fails AEAD unambiguously. The failing `(chunk_hash, shard_index)` is exactly the shard that needs repair.
- After EC reconstruction, the recovered chunk plaintext is hashed and compared to `chunk.chunk_hash` (BLAKE3 or vault-salted, per §7.9). A mismatch here indicates a defense-in-depth failure (e.g., implementation bug producing wrong plaintext from authentic shards) — the chunk is marked LOST and the read fails with `chunk_integrity_violation` (Invariant I4).

### 6.5 Read Repair (inline)

```
During §6.4, if shard verify fails:

  Engine:
    mark that shard DEGRADED in metadata (CRDT op: LWW_SET)
    enqueue REPAIR_HIGH_PRIORITY in repair scheduler
    do NOT fail the read — let the K-of-N reconstruction continue
    if a hedge can serve the missing shard, prefer it

  Concurrently, repair scheduler:
    pop top item (this DEGRADED shard, score boosted by recency)
    fetch a healthy replica of the same shard or reconstruct from K
    re-encrypt? no — same chunk content, same shard bytes
    place fresh shard via placement engine on a different driver
    on success: mark HEALTHY; CRDT op records new replica

Result: read completes from K healthy shards; degradation is repaired
within seconds rather than waiting for next scheduled scrub.
```

**Why per-shard repair targeting is unambiguous**: AEAD verification with AAD = `chunk_hash || shard_index` (§8.2) happens *per shard* and *before* EC decode. A failed AEAD identifies exactly one (chunk, slot) pair as the bad one — there is no triangulation problem. K shards that pass AEAD are by construction the right shards for this chunk in their respective slots; EC decode of K authentic shards is deterministic.

**Insufficient-K branch** (fewer than K shards verify even after exhausting hedges):

```
If, after all K + H initial fetches and all reachable additional replicas have been tried,
fewer than K shards pass AEAD verification:

  Engine:
    mark every failed shard DEGRADED + enqueue HIGH-priority repair
    if no further replicas are reachable for the missing slots:
      mark chunk replication_state = LOST
      emit `chunk.lost` event referencing affected file(s) (Invariant I4)
      fail the read with `chunk_unrecoverable`
    else:
      continue firing hedges; once K verify, complete the read normally

  Subsequent reads of the same chunk see chunk_state = LOST and fail fast
  until repair (from a remaining healthy replica or from a peer device's cache)
  restores ≥ K healthy shards.
```

This is the cliff that triggers Invariant I4 ("no silent data loss"): the user is told *per file* which chunks are unrecoverable, rather than the read returning corrupted data or hanging.

### 6.6 Differential Snapshot

Engine enumerates dirty pages. Builds delta blob (page_id + page_version + opaque payload). Encrypts under snapshot key. Hashes. Uploads as `snapshot.<ts>.delta` via vault plugin. Verifies. Atomically updates `snapshot.current` (signed, monotonic). Truncates WAL up to delta cutoff. Updates Merkle tree leaves for affected pages. Replicates to other configured vaults.

### 6.7 Anti-Entropy Merkle Reconciliation

```
Vault Mgr (this device)         Vault Provider A          Vault Provider B
        │                              │                         │
        │ scheduled tick               │                         │
        ├─────────────────────────────►│                         │
        │ GET merkle.root              │                         │
        │◄─────────────────────────────┤                         │
        │ compare to local root        │                         │
        │ ───────────────────────────────────────────────────►│
        │ GET merkle.root from B                                 │
        │◄───────────────────────────────────────────────────────┤
        │                                                        │
        │ if all roots equal → done                              │
        │                                                        │
        │ if A vs local differ:                                  │
        │   walk down: GET merkle.subtree?path=…                 │
        │   ──────────────────────────►│                         │
        │   ←──────────────────────────┤                         │
        │   identify divergent leaf range                        │
        │   GET pages in range                                   │
        │   ──────────────────────────►│                         │
        │   ←──────────────────────────┤ (only differing pages)  │
        │   apply via CRDT WAL replay                            │
        │   re-derive Merkle leaves                              │
        │                                                        │
        │ same loop for B                                        │
```

- Bandwidth: O(d) hashes for divergence walk plus O(differing pages), where d = tree depth.
- Cassandra/Riak/Dynamo standard pattern; well-understood, fast.

### 6.8 CRDT Multi-Device Merge

Two devices write concurrently. WAL exchanged via vault providers (or directly via P2P over user's private network if configured). Each device replays peer's WAL, applies CRDT op semantics, derives identical merged state. HLC + op kind ensures determinism.

### 6.9 Repair Scheduler

```
sources of work:
  • Background scrubber (5%/day sample)
  • Read-repair detection (high priority)
  • Plugin health-changed events (entire driver quarantined → mass enqueue)
  • Provider quota warning (proactive migrate-out)

priority score:
  urgency = (replicas_floor - current_healthy) × W_floor
          + recency_bonus(last_modified)
          + access_bonus(access_count_window)
          + hot_data_bonus(is_recently_read)

queue:
  bounded priority heap, capped size with overflow → demoted to scrub
  worker pool drains, calling placement engine
  rate-limited to not burn provider rate-limit budget
```

### 6.10 Sharing

Owner POSTs share → Identity & Share Manager unwraps file key with MK → wraps under recipient KEM pubkey → appends to FILE.wrapped_keys → produces signed share_blob → user transmits OOB → recipient imports → recipient's engine verifies signature, mounts under `/shared-with-me/...`.

Revocation: rotate file key → re-encrypt chunks → remove recipient's wrap entry. Already-cached plaintext on recipient's side cannot be recalled (fundamental).

### 6.11 Vault Destruction

Crypto-shred MK → overwrite recovery manifest → best-effort delete on all backends → user receives residual public-exposure report.

### 6.12 Plugin Sandboxed Call

Engine → Plugin Host → enters WASM sandbox → plugin calls `signed_fetch(handle, request)` → host injects auth → fires HTTP on allowlisted host → response body returns to plugin → plugin returns ciphertext to engine. Tokens never leave host.

### 6.13 Namespace Projection at Read Time

Every namespace-shaped API call (`GET /dirs/{path}`, `HEAD /files/{path}`, path-targeted reads/writes/deletes) resolves through the same projection function. The engine never stores a tree — it computes one when asked.

```
project(query_path, kind):
  # 1. Gather candidate FILE/DIR records by indexed prefix scan on `path` field
  candidates = metadata.scan_by_path_prefix(query_path)

  # 2. Apply same-path collision rule (§5.8.3 N2)
  by_path : map<rendered_path, record>
  for r in candidates:
      rendered = r.path
      if rendered already claimed by record r':
          # HLC + file_id deterministically picks loser
          loser, winner = order_by_hlc(r, r')
          conflict_path = f"{loser.path}.conflict-{loser.hlc}-{loser.file_id[:8]}"
          by_path[winner.path]   = winner
          by_path[conflict_path] = loser
      else:
          by_path[rendered] = r

  # 3. Apply implicit-directory rule (§5.8.3 N3)
  if kind == DIR_LISTING:
      direct_children    = entries directly under query_path
      implicit_subdirs   = derived from FILE records with deeper prefix
      explicit_subdirs   = DIR records with path == query_path/X
      tombstoned_dirs    = explicit DIRs that were OR_SET_REMOVEd
      # tombstoned dirs are resurrected if any FILE under them survives
      return direct_children ∪ implicit_subdirs ∪ (explicit_subdirs − tombstoned_dirs_with_no_surviving_descendant)

  if kind == FILE_LOOKUP:
      return by_path[query_path]   # may be a winner OR a conflict-rendered loser
```

**Properties**:
- **Deterministic**: every device with the same merged WAL produces the same projection. HLC + file_id break all ties.
- **Idempotent**: repeated calls return identical results until a relevant op is applied.
- **Cheap**: a path-prefix index on `FILE.path` (LSM secondary index) makes `GET /dirs/{path}` O(matches) plus a small constant for collision/dir-resurrection bookkeeping.
- **Stable IDs**: `file_id` never changes across a rename, move, or copy of the path label. Sharing, recipient wraps, and external references key on `file_id`, not on `path`.

Frontends consume this projection through the existing API; no frontend-side change is required relative to the prior tree-CRDT framing.

---

## 7. Distributed Strategy Patterns (Summary)

This section consolidates the production-grade patterns used in §6 for quick reference.

| Pattern | Purpose | Origin / cite |
|---|---|---|
| **Quorum acks (W = k+1)** | Fast durable writes; remaining shards async | Cassandra, Storj, MinIO |
| **Hedged reads (K + H)** | Reduce 99.9p tail latency dramatically | Dean & Barroso, "The Tail at Scale" (2013, CACM) |
| **Inline read repair** | Repair within milliseconds, not days | Cassandra, Dynamo |
| **Merkle anti-entropy** | Efficient cross-replica reconciliation | Cassandra, Riak, Dynamo |
| **Priority repair queue** | Repair near-floor data first | Ceph |
| **Bloom filter dedup** | Fast existence check | Standard in dedup systems (LBFS, restic, borg) |
| **Tiny-file inlining** | Eliminate metadata overhead for small files | SeaweedFS, modern object stores |
| **CRDT WAL with HLC** | Multi-device merge without coordination | Yjs, Automerge, Ditto |
| **Reed–Solomon EC (k-of-n)** | Storage-efficient redundancy | Ceph, Storj, MinIO, Tahoe-LAFS |
| **CDC + compress + pad + pack** | Defeat keyed-CDC algebraic attack | Truong (2024) |
| **WASM-sandboxed plugins** | Safe extensibility | Modern best practice |

### 7.1 Patterns Considered and Deliberately Rejected

| Pattern | Why we don't use it |
|---|---|
| **LRC / regenerating codes** | Reed-Solomon at k=4, n=7 is fine; LRC adds complexity and recent surveys flag wide-stripe LRC reliability gotchas |
| **Pipelined chained writes (GFS-style)** | Parallel fan-out is correct for heterogeneous backends; chaining slows tail |
| **Convergent encryption** | Enables cross-file dedup but vulnerable to confirmation attacks; per-file random nonce is safer |
| **Tied requests (cancellation hints)** | Marginal gain over hedged; reconsider if hedge load becomes a problem |
| **Strong-read quorum on every read** | Overkill for our workload; verification via AEAD tag + read-repair gives correctness without latency cost |

### 7.2 Dynamic EC Selection

The EC scheme is not fixed. It adapts to the available pool at write time:

```
At chunk write:
  available_groups = distinct trust-correlation groups
                     among healthy plugins meeting capability requirements
  N_max            = config.redundancy.ec.n_max (default 13)
  K_target         = config.redundancy.ec.k (default 4)
  N_chosen         = min(available_groups, N_max)
  if N_chosen < K_target + 1:
    fall back to replication (factor = available_groups)
  else:
    EC scheme = (K_target, N_chosen)
```

- The chosen scheme is recorded in `chunk.ec_scheme` so different chunks may have different schemes.
- The rebalancer (§7.4) re-encodes chunks if the pool grows enough to justify a wider scheme for cold data.
- Going wider requires more diverse trust groups, not just more plugins.

### 7.3 Capacity-Weighted CRUSH-Style Placement

The placement engine uses a deterministic pseudo-random function over `(chunk_hash, shard_index)`, weighted by per-plugin capacity and health:

```
For chunk hash H, shard index i, plugin pool P:
  weights[p] = remaining_quota(p)
             × health_score(p)
             × tier_match(p, chunk.tier)
             × user_weight(p)
  candidate  = consistent_hash(H || i, weights)
  enforce diversity: if candidate.trust_group already used
    by prior shards of this chunk, advance to next-best
  return candidate
```

Properties:
- **Deterministic**: same chunk hash + same pool → same placement. No central placement table.
- **Stable**: adding/removing one plugin re-places only ~1/N of chunks (consistent-hashing property).
- **Capacity-aware**: a 4 TB NAS plugin draws proportionally more shards than a 15 GB Drive plugin.
- **Diversity-aware**: trust-correlation graph enforced.

Inspired by [Ceph CRUSH](https://ceph.io/assets/pdfs/weil-crush-sc06.pdf), simplified for our single-level hierarchy (trust groups only).

### 7.4 Rebalancer

A long-running background component triggered by:
- Plugin added → migrate fraction of existing shards toward the new plugin (better diversity, more capacity used).
- Plugin removed (`migrate-out` API) → drain all shards off it.
- Plugin capacity changed materially → re-weight placement.
- Tier reclassification (hot → cold, etc.) → move chunks across tiers.
- EC scheme upgrade for cold data → re-encode using the wider scheme.

```
rebalancer loop (low-priority, throttled):
  enqueue affected chunks by reason and priority
  for each chunk:
    decide target placement using current CRUSH weights
    if differs from current placement:
      schedule re-place (uses repair scheduler's worker pool)
      respect bandwidth_cap to not interfere with foreground I/O
  resumable across engine restarts (state in metadata)
```

### 7.5 Tier Classification (hot / warm / cold)

```
tier(chunk) = derive from access_count_window:
  hot    : > N_h reads in last 7 days
  warm   : 1–N_h reads in 7 days
  cold   : 0 reads in > 30 days (or freshly written, see exception)

Per-tier policy (defaults, configurable):
  hot     : K=4, N=7,  prefer fast/clean backends, lower hedge_after_ms
  warm    : K=4, N=7,  default placement
  cold    : K=8, N=12, prefer cheap/slow backends, wider EC for storage savings

Exception: a fresh chunk has no access history; treat as warm by default.
```

Tier changes trigger the rebalancer. Repair scheduler also takes tier into account: hot data has lower repair priority floor (more redundancy expected always); cold data has more relaxed thresholds.

### 7.6 Pool-Aware Capacity Planner

```
report on demand:
  total_usable_bytes  = Σ over plugins of (remaining_quota × K/N efficiency)
                        - reserved_for_metadata - shadow_overhead
  per_plugin_share    = each plugin's contribution
  shadow_overhead     = bytes of shadow registry entries weighted by
                        whether the plugin counts them against quota
  fill_rate           = bytes/day, rolling 30-day median
  projected_full_at   = now + (free / fill_rate)

emit events:
  capacity.projection_updated  when projection changes by >1 day
  capacity.threshold_warning   when projected_full_at < 14 days
  capacity.threshold_critical  when projected_full_at < 3 days
```

### 7.7 Untrusted-Quota Mode

When a plugin's reported `quota_used_bytes` repeatedly diverges from observed write success (e.g., write fails with `quota_exceeded` while plugin reports 50% free), the engine probes via small test writes. Persistent dishonesty places the plugin in `untrusted_quota` state: the planner uses a probed effective capacity rather than the plugin's self-report. User notified via `provider.quota_untrusted` event.

### 7.8 Plugin Capability Drift

```
on plugin (re-)load:
  diff manifest.capabilities vs. last_known_capabilities
  for each LOST capability that affects placed chunks:
    require user confirmation; otherwise rebalance affected chunks away
  for each GAINED capability:
    hot-load; future placements may use new capability
  emit plugin.capability_changed { plugin_id, gained, lost }
```

A plugin that loses `supports_delete` (perhaps the upstream backend changed policy) cannot silently leave us unable to GC. The user is shown the change and offered an automated migrate-out.

### 7.9a Metadata Compression

Metadata pages are compressed with zstd against a per-vault trained dictionary. The dictionary version is recorded in the vault root. On compaction, the engine samples ~1% of metadata pages, retrains the dictionary if needed, and recompresses. Saves ~30–50% of metadata footprint at vault scale, extending the effective size of the 15 GB metadata budget.

### 7.9 Plaintext-Hash Salting Mode

Each vault selects a `chunking.hash_mode`:

| Mode | Chunk hash | Dedup scope | Side-channel |
|---|---|---|---|
| `vault_salted` (default for new vaults) | `BLAKE3(vault_salt \|\| plaintext)` | Within this vault only | None — vault salt is private |
| `global_blake3` (legacy) | `BLAKE3(plaintext)` | Across vaults using same mode | Vault provider could correlate hash to a known plaintext file |

The vault salt is derived from MK under `kp:vault-salt`. It's the same on all of the user's devices; cross-device dedup within a vault still works.

---

## 8. Encryption Design

### 8.1 Key Hierarchy with Enumerated Purposes

```
              User passphrase
                    │
              Argon2id(salt, profile-driven params)
                    │
                    ▼
              ┌──────────┐
              │ Master   │
              │ Key (MK) │
              └────┬─────┘
                   │ HKDF(MK, info=key_purpose, salt=…)
                   │
   ┌───────────────┴────────────────────────────────────────────────┐
   ▼               ▼               ▼               ▼                ▼
 kp:file        kp:snapshot    kp:lease-sign   kp:cred-wrap   kp:share-identity
   │               │               │               │                │
   │ HKDF(file_key,                                │       ┌────────┴────────┐
   │      chunk_index)                             │       ▼                 ▼
   ▼                                               ▼  kp:share-kem      kp:share-sign
 chunk key                                    OAuth token   (ML-KEM)        (Ed25519)
                                              wrap key
                                                   ▲
                                                   │
                                                kp:device
                                                (per-device sign key)
                                                kp:cdc-secret
                                                (CDC chunking secret,
                                                 only when CDC enabled)
```

Reserved purposes:
- `kp:file`, `kp:snapshot`, `kp:lease-sign`, `kp:cred-wrap`
- `kp:share-identity`, `kp:share-kem`, `kp:share-sign`
- `kp:device`, `kp:cdc-secret`, `kp:bloom-salt`
- Reserved-but-unused: `kp:future-1` … `kp:future-8`

### 8.2 AEAD

- **Default**: ChaCha20-Poly1305.
- **Hardware-accelerated**: AES-256-GCM on AES-NI / ARMv8 crypto.
- Random per-shard nonce; AAD = `chunk_hash || shard_index`.

### 8.3 KDF Profiles

| Device class | Memory | Iterations | Parallelism |
|---|---|---|---|
| Desktop | 512 MiB | 3 | 4 |
| Modern phone | 256 MiB | 3 | 2 |
| Low-RAM phone | 64 MiB | 5 | 1 (surfaced honestly) |

### 8.4 Asymmetric Primitives

- **Ed25519** for: lease, snapshot pointer, share signatures, per-device WAL signatures, identity-key signing.
- **ML-KEM-768** for: per-recipient share key wrapping (PQ-safe).
- **ML-DSA-65** (optional): post-quantum signatures for archival shares.

### 8.4.1 Identity Signature Chain

Identity is versioned by `epoch_id`. Each rotation creates a new epoch whose pubkey is signed by the previous epoch's key. Snapshot pointers and shares carry the epoch they were signed under.

```
identity_chain stored in recovery manifest:
  [
    { epoch: 0, sign_pubkey: P0, kem_pubkey: K0,
      fingerprint: F0,
      signed_by: <self-signed at vault creation> },
    { epoch: 1, sign_pubkey: P1, kem_pubkey: K1,
      fingerprint: F1,
      signed_by_epoch_0: <Ed25519 sig over (P1,K1) using P0> },
    { epoch: 2, sign_pubkey: P2, kem_pubkey: K2,
      fingerprint: F2,
      signed_by_epoch_1: <Ed25519 sig over (P2,K2) using P1> },
    …
  ]

snapshot pointer signature:
  { epoch_id, version_counter, snapshot_id, signature_using_epoch.sign_pubkey }

cold start verification:
  walk identity_chain from epoch 0 forward
  verify each link's signature against the previous epoch's pubkey
  current valid identity = last epoch in the chain
  reject snapshot pointers whose epoch isn't in the validated chain
```

Lost a chain link → recovery fails honestly (rather than silently accepting a forged identity). Rotating the identity (e.g., after suspected compromise) appends a new epoch; old shares signed under prior epochs continue to verify against the chain.

#### 8.4.2 Where the Chain Lives — Cold-Start Trust Anchor

The chain MUST be reachable **before** the snapshot is loaded, because the snapshot pointer's signature is verified against the current epoch's key. Storing the chain only inside the snapshot creates a circular dependency.

The chain is therefore stored in **two places**:

1. **`RecoveryManifest.identity_chain`** — primary trust source on cold start. Encrypted under MK; tamper-resistant. The recovery manifest itself is fetchable from any vault provider and decryptable by anyone with MK. Updates to the chain (rotation) update this field.
2. **`Vault.identity_chain` inside metadata snapshots** — runtime convenience copy; matches the manifest's chain. Used at runtime so identity ops don't always re-fetch the manifest.

#### Cold-Start Sequence (post-fix)

```
1. user supplies recovery materials
   ──► crypto/.derive_master_key → MK

2. fetch encrypted RecoveryManifest from any vault provider
   (the manifest's location is known: a fixed path in vault, e.g., "recovery.manifest")
   ──► crypto/.decrypt with MK ──► manifest

3. verify manifest's identity_anchor_fingerprint matches BLAKE3-160(epoch_0.sign_pubkey)
   ──► trust anchor established

4. walk manifest.identity_chain forward
   for each epoch_n: verify signed_by_prev with epoch_{n-1}.sign_pubkey
   ──► validated current epoch = last in chain

5. fetch SignedSnapshotPointer (vault path: "snapshot.current")
   verify pointer.signature against validated current epoch's sign_pubkey
   verify pointer.version_counter > local last_seen
   ──► trusted snapshot pointer

6. fetch encrypted snapshot pages
   crypto/.decrypt with snapshot key (HKDF subkey of MK)
   ──► metadata loaded

7. (cross-check) compare Vault.identity_chain inside loaded metadata against manifest.identity_chain
   - identical → fine.
   - snapshot's chain is a strict prefix of manifest's chain (snapshot lags) → fine. Trigger background "refresh snapshot chain from manifest" (write a fresh LwwRegister op so future snapshots converge).
   - manifest's chain is a strict prefix of snapshot's chain (manifest lags) → **suspicious**. The manifest is the trust anchor; if it's behind the snapshot, either the manifest hasn't been pushed yet on this provider (recoverable: try other binding-listed providers) OR the manifest has been tampered with (unrecoverable here).
   - chains diverge (neither is a prefix of the other) → forked state; refuse. Emit `identity.chain_forked`.
   - on any non-recoverable mismatch: emit `identity.chain_invalid` and refuse to operate.
```

**Authority rule (AD-2)**: The RecoveryManifest's `identity_chain` is the **authoritative** source. The snapshot's `Vault.identity_chain` is a runtime cache that is refreshed from the manifest at every snapshot rotation. If the cache lags, the engine corrects it; if the cache is *ahead* of the manifest, that's a serious anomaly indicating either a partial-sync state on the chosen vault provider (try another) or tampering (refuse).

Step 3 is the single point of trust. Anchor compromise = chain compromise. Anchor is a 20-byte fingerprint baked into the recovery manifest at vault creation, signed under MK; tampering it requires MK or breaking AEAD.

### 8.5 CDC Attack Mitigation

When `chunking.strategy = content-defined`, the engine **automatically enables**:
- **Compression**: zstd before chunking, so chunk boundaries don't reveal plaintext sizes directly.
- **Padding**: each chunk padded to next power-of-two within bounds.
- **Packing**: small chunks coalesced into a fixed-size container before EC.

These mitigate the algebraic attack on keyed-CDC chunking secrets (Truong, 2024). They cost ~5–10% storage overhead but defeat a known real attack on Borg/Restic/Tarsnap-class systems.

### 8.6 Recovery, Crypto-Shredding

(Same as previous: passphrase / recovery file / Shamir / hardware key. Vault destruction overwrites MK; surviving ciphertext becomes random.)

---

## 9. Failure Model

| Failure | Detection | Response |
|---|---|---|
| Single shard corrupt | Inline read repair (§6.5) or scrub | Repair scheduler high-priority enqueue → re-place |
| Shard upload ack timeout | Placement engine | Re-route to fresh driver; quorum still met if W < N attempted |
| Backend account banned | Plugin auth error | Quarantine → mass-enqueue all shards from that driver into repair scheduler |
| Backend service shut down | Plugin endpoint error | Same, plus permanent disable |
| Metadata vault provider lost | Snapshot upload fail | Promote replica vault; anti-entropy reconciles others |
| Vault replicas diverge | Merkle root mismatch | Pull divergent pages; CRDT WAL replay reconciles |
| All metadata vaults lost | n/a | Recovery via Shamir / file → bind to new vault |
| Local device lost | n/a | Restore from snapshot + WAL on new device |
| Master key lost (no recovery) | n/a | Data unrecoverable, by design |
| EC threshold breached | Scrubber finds <K healthy | Per-file user notification; chunk LOST |
| Plugin crash | WASM trap or panic | Plugin isolated; failover to alternative driver |
| Concurrent device write | n/a | CRDT merge resolves |
| Format version mismatch | Snapshot header | Run migration; refuse downgrade |
| Device revoked | Revoked device tries to sync | Engine refuses; user gets `device.revoked` event |
| Bloom false positive | Metadata lookup falls through | Negligible cost; correctness preserved |
| Hedge fires too aggressively | Provider rate-limit | Adapter backs off `hedge_after_ms` upward |

---

## 10. Garbage Collection

```
mark phase:
  walk file table → collect referenced chunk hashes per recipient
  refcount each chunk

sweep phase (background, throttled):
  for each chunk where refcount == 0:
    for each shard:
      call driver.delete(handle), inspect DeleteResult.outcome:
        removed     → drop shard record entirely
        tombstoned  → register SHADOW with tombstone_clears_at;
                      schedule re-peek; drop on clearance
        abandoned   → register SHADOW (cannot reclaim);
                      shard record removed from chunk
        not_supported → register SHADOW (plugin honest about no-delete)
        not_found   → drop shard record (already gone)
    when all shards removed or shadowed: remove chunk record
    update Bloom filter (lazy: on next snapshot rebuild)

shadow management (continuous):
  for each SHADOW with tombstone_clears_at:
    after the timestamp, peek the handle:
      not_found → drop shadow (truly gone)
      exists    → keep shadow; bump check interval
  for each SHADOW with reason=update_replaced or repair_replaced:
    same logic — opportunistically retry delete if plugin gained capability

compact phase:
  rewrite pages omitting tombstones
  compact WAL up to last full snapshot
  rebuild Bloom filter (cheap; ~60 MB)
  rebuild Merkle leaves for changed pages
  emit quota.unreclaimable_growing event if shadow bytes
    on any driver exceed configured threshold
```

**Repair scheduler runs concurrently** with GC; both share the rate-limit budget pool.

**Vault destruction** explicitly drains the shadow registry as part of its residual-exposure report: every shadow on every backend is listed with `cached_elsewhere_risk` so the user sees exactly what ciphertext could not be removed. Crypto-shred (master-key zeroize) makes those shadows information-theoretically random; they cost backend quota but cannot leak the user's data.

---

## 11. Configurable Parameters

### 11.1 Chunking
| Parameter | Default | Range |
|---|---|---|
| `chunking.strategy` | `fixed` | `fixed` / `content-defined` |
| `chunking.size` | 4 MB | 64 KB – 64 MB |
| `chunking.cdc_min` | 1 MB | (CDC only) |
| `chunking.cdc_max` | 16 MB | (CDC only) |
| `chunking.cdc_attack_mitigations` | enabled-when-cdc | enabled / disabled |

### 11.2 Tiny-File Inline
| Parameter | Default | Range |
|---|---|---|
| `inline.threshold_bytes` | 4096 | 0 – 65536 |

### 11.3 Redundancy
| Parameter | Default | Range |
|---|---|---|
| `redundancy.mode` | `erasure` | `erasure` / `replication` |
| `redundancy.ec.k` | 4 | 2 – 16 |
| `redundancy.ec.n` | 7 | k+1 – 32 |
| `redundancy.replication_factor` | 3 | (replication mode) |
| `redundancy.write_acks_required` (W) | k+1 (=5) | k+1 – n |
| `redundancy.repair_floor` | k+1 | |
| `redundancy.diversity_groups_min` | 2 | 1 – 5 |

### 11.4 Read Path
| Parameter | Default | Range |
|---|---|---|
| `read.hedge_count` | 2 | 0 – 8 |
| `read.hedge_after_ms` | adaptive (max(250, p95)) | 50 – 5000 |
| `read.hedge_max_load_pct` | 5% | extra load cap |
| `read.repair_inline` | true | true/false |

### 11.5 Repair Scheduler
| Parameter | Default | Range |
|---|---|---|
| `repair.concurrency` | 8 | 1 – 64 |
| `repair.urgency_floor_weight` | 10 | |
| `repair.urgency_recency_weight` | 3 | |
| `repair.urgency_access_weight` | 2 | |
| `repair.queue_max_size` | 100000 | |

### 11.6 Anti-Entropy
| Parameter | Default | Range |
|---|---|---|
| `anti_entropy.merkle_depth` | 15 | 10 – 20 |
| `anti_entropy.exchange_interval` | 1 hour | 5 min – 24 h |
| `anti_entropy.bandwidth_cap_kbps` | 5000 | |

### 11.7 Encryption
| Parameter | Default |
|---|---|
| `crypto.aead` | `auto` (chacha20 unless AES-NI) |
| `crypto.kdf` | `argon2id` |
| `crypto.kdf.profile` | auto-detected |
| `crypto.signature` | `ed25519` |
| `crypto.kem` | `ml-kem-768` |

### 11.8 Snapshot & WAL
| Parameter | Default |
|---|---|
| `snapshot.delta_interval` | 30 min idle / immediate on close |
| `snapshot.full_compaction_after_n_deltas` | 50 |
| `snapshot.wal_flush_interval` | 30 s |
| `snapshot.versions_retained` | 7 |
| `snapshot.verify_after_upload` | true |

### 11.9 Vault Replication
| Parameter | Default |
|---|---|
| `vault.providers` | (user list) |
| `vault.replicate_count` | 2 |
| `vault.read_strategy` | `freshest` |

### 11.10 Lease (advisory)
| Parameter | Default |
|---|---|
| `lease.ttl` | 5 min |
| `lease.steal_threshold` | 2 × TTL |

### 11.11 Local Cache
| Parameter | Default |
|---|---|
| `cache.metadata_max_bytes` | 8 GB |
| `cache.read_cache_max_bytes` | 2 GB |
| `cache.write_staging_max_bytes` | 1 GB |
| `cache.prefetch` | `sequential` |

### 11.12 Bloom Filter
| Parameter | Default |
|---|---|
| `bloom.target_fpr` | 0.01 |
| `bloom.expected_chunks` | 50_000_000 |
| `bloom.rebuild_on_compaction` | true |

### 11.13 Plugins / Backends
| Parameter | Default |
|---|---|
| `plugin.thirdparty.enabled` | false |
| `plugin.thirdparty.allowed_legal_classes` | `green,yellow` |
| `plugin.network.proxy` | none |
| `drivers.<id>.weight` | 1.0 |
| `drivers.<id>.rate_limit.rps` | per-driver |
| `drivers.<id>.health_floor` | 0.4 |

### 11.14 GC
| Parameter | Default |
|---|---|
| `gc.scrub_sample_rate` | 5%/day |
| `gc.delete_attempt_retries` | 5 with exp backoff |
| `gc.compaction_interval` | weekly |

### 11.15 Recovery
| Parameter | Default |
|---|---|
| `recovery.modes` | (user choice) |
| `recovery.shamir.k_of_n` | 3 of 5 |

---

## 12. Plugin Framework

See `PLUGIN_SDK.md`.

---

## 13. Cold Start

```
1. Pair with engine.
2. Passphrase + recovery components.
3. Engine derives MK.
4. Bind to vault provider(s).
5. Fetch latest snapshot pointer + manifest.
6. Fetch top-of-namespace metadata pages.
7. Frontend can browse within ~30 s.
8. Background-fetch deeper pages on demand.
9. Background-replay WAL since snapshot.
10. Background-pull peer WAL for CRDT merge.
11. Background-rebuild Bloom filter.
12. Background-anti-entropy with replica vaults.
```

---

## 14. Multi-Device

CRDT-encoded WAL baseline. HLC-ordered. Per-device signing key. Lease advisory. Concurrent writes merge deterministically. Device revocation rotates `kp:device` for revoked device; their next sync fails verification.

---

## 15. Sharing & Identity Model

Identity = `{sign_pubkey, kem_pubkey}` derived under reserved purposes. Out-of-band peer exchange (no central directory). Per-recipient key wraps in `wrapped_keys` list. Revocation rotates file key + re-encrypts chunks + removes wrap. Group shares = N independent recipients (no group key).

### 15.1 Republisher Hint (owner-offline resilience)

A `share_blob` may carry an optional `republisher_hint`: a list of one or more provider locators the recipient may pin the shared chunks to under their own plugins. This solves the case where the owner is offline at the moment a recipient tries to read.

```
share_blob {
  share_id, scope, recipient_id, wrapped_keys_ref,
  signature_by_owner, expires_at,
  republisher_hint: optional [
    { provider_id_in_recipient_pool, copy_chunks: bool }
  ]
}
```

If `republisher_hint` is present and the recipient accepts, the recipient's engine may pin (re-upload-as-encrypted-bytes) the shared chunks into their own configured plugins. The chunks remain encrypted with the same shared key — the recipient never sees plaintext until decryption, and the file key remains controlled by the owner. The owner is notified via `share.republished` event.

This converts a share from "owner serves" to "shared chunks live in recipient's pool too" — fixes RESILIENCE §2.G.1 (owner offline). Revocation still works: rotating the file key invalidates all wrappings; new ciphertext fetches fail; plaintext already cached on the recipient's side cannot be recalled (fundamental, documented honestly).

---

## 16. Format Versioning & Migrations

All blobs versioned. Online forward-only migrations. Snapshot pages opaque envelopes; record-format evolution doesn't affect snapshot layer. Plugin SDK semver.

---

## 17. Concurrency & Locking

| Scope | Mechanism |
|---|---|
| Inter-device write | CRDT WAL merge; advisory lease |
| Inter-vault reconciliation | Merkle-guided pull |
| Intra-device, multi-process | OS file lock |
| Intra-process, multi-thread | RW locks on metadata pages |
| Plugin call serialization | Per-plugin worker pool |
| WAL append | Append-only with HLC |
| Repair scheduler | Bounded priority queue, mutex |

---

## 18. Self-Hosted Mode

Same engine as daemon on user's NAS / server. Frontends consume API over private network with mTLS. Plugins run in daemon. No service we operate.

---

## 19. Observability

- Local logs only.
- Metrics at `/v1/system/metrics` (Prometheus exposition); user's own scrape.
- Crash dumps local; user shares manually.
- Frontends subscribe to event stream; can surface health prominently.

---

## 20. Out of Scope

- Server we operate.
- Default-on red drivers.
- Non-encrypted on-cloud state.
- Real-time peer co-editing.
- Plausible deniability (future).
- Default cover-traffic mode (opt-in).

---

## 21. Open Questions

1. **Local KV engine**: LSM (expected) vs. B-tree.
2. **WAL serialization format**: protobuf / flatbuffers / cap'n proto / CBOR.
3. **Mobile background-fetch budget** on cellular vs. wifi.
4. **Plugin discovery**: community-maintained signed list.
5. **Identity exchange UX**: best practices for QR / paper.
6. **Adaptive hedge tuning**: how much load is acceptable to chase tail latency?
7. **LRC migration**: when (if ever) to switch from RS to LRC for cold archival.
8. **CDC dedup gain measurement**: collect anonymous local stats so users see whether CDC helps their workload.

---

## 22. Glossary

- **Engine**: the core process exposing the API.
- **Frontend**: any client of the API (CLI, app, web, mobile, FUSE shim).
- **Vault**: the user's complete encrypted namespace.
- **Master**: the authoritative metadata store on the local device.
- **Vault provider**: a plugin holding the metadata vault.
- **Chunk backend**: a plugin holding encrypted chunk shards.
- **Shard**: one of the EC pieces of an encrypted chunk.
- **Lease**: advisory primary-writer hint.
- **Trust-correlation group**: provider grouping for diversity.
- **Recovery manifest**: encrypted blob capturing recovery configuration.
- **Crypto-shred**: deletion of master key.
- **HLC**: Hybrid Logical Clock — physical time + logical counter.
- **Identity**: user's signing + KEM keypair.
- **Peer**: another user's identity known to this user.
- **Share**: per-recipient key wrap.
- **Self-hosted mode**: engine running as user-owned daemon.
- **Quorum (W)**: number of shard acks required to declare a write durable.
- **Hedged read**: redundant fetches with cancellation, to reduce tail latency.
- **Read repair**: inline shard repair triggered by verify failure during a read.
- **Anti-entropy**: Merkle-tree-guided reconciliation between vault replicas.
- **Bloom filter**: probabilistic existence check over chunk hashes.
- **Inline payload**: tiny file stored directly inside its FILE record without chunking.
- **Repair scheduler**: prioritized queue for shard repair work.
