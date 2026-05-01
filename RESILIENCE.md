# OpenStorage — Core Resilience & Invariants

> **Purpose**: this document is the source of truth for what the core promises *regardless of how plugins behave*. The architectural goal is: **the core is strong; plugins can be anything**. Any plugin that satisfies the contract (`put / get / peek / delete / health`) — clean cloud, hostile service, NAS, comments section, anything — is acceptable, and the core preserves all invariants below regardless.
>
> **Read alongside**: [`DESIGN.md`](./DESIGN.md), [`PLUGIN_SDK.md`](./PLUGIN_SDK.md), [`API.md`](./API.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## 1. The Ten Core Invariants

Every other section of this document is in service of these. If any plugin behavior would violate one of them, the resolution policy preserves the invariant — usually by quarantining or compensating, not by failing.

| # | Invariant | Maintained by |
|---|---|---|
| I1 | **Confidentiality**. No backend, plugin, network observer, or third party ever sees plaintext. | Client-side AEAD (ChaCha20-Poly1305 / AES-256-GCM); plaintext never crosses the API boundary unencrypted. |
| I2 | **Integrity**. Tampered ciphertext is detected before it's returned to a caller. | AEAD tag + chunk hash + signed snapshot pointer. |
| I3 | **Availability under partial failure**. Loss of any subset of plugins ≤ (N − K) does not lose data. | Erasure coding 4-of-7 default + diversity rule + repair scheduler. |
| I4 | **No silent data loss**. If data becomes irrecoverable, the user is told which files. | Scrubber + repair scheduler + `chunk.lost` events. |
| I5 | **No silent storage leaks**. Every byte placed on a backend is referenced (active shard) or recorded (shadow). | Shadow registry + handle-change demotion (§5) + GC outcome routing. |
| I6 | **Eventual consistency across the user's devices**. Given enough sync time, all devices converge. | CRDT WAL with HLC + Merkle anti-entropy + signed monotonic snapshot pointer. |
| I7 | **Deterministic cold start**. A fresh device with the master key + a vault pointer reproduces an identical view. | Signed snapshot pointer + WAL replay + identity-key signature chain. |
| I8 | **Plugin malfeasance is contained**. A buggy/malicious/compromised plugin cannot exfiltrate keys, plaintext, or affect other plugins. | WASM sandbox + signed_fetch + per-plugin allowlist + capability flags. |
| I9 | **Honest accounting**. Reported "free space" is the truth; orphans and shadows are surfaced. | Pool-aware capacity planner + shadow registry + per-driver shadow accounting. |
| I10 | **Quorum durability**. Once a write returns 201, it survives any subsequent loss of (N − W) backends. | Quorum-W ack + capacity-weighted placement + diversity check at placement time. |

---

## 2. The Catalog of Edge Cases — and How We Resolve Each

Every edge case identified across the design conversation, organized by domain, with the resolution policy.

### 2.A — Plugin Misbehavior

#### 2.A.1 Plugin returns a new handle when the engine expected an in-place overwrite
**Resolution**: handled by `PutResult` (`PLUGIN_SDK.md` §5.2). `handle_changed=true` + `prior_handle_state` tells the engine exactly what happened. `abandoned`/`tombstoned`/`unknown` → register a SHADOW SHARD. *I5 preserved.*

#### 2.A.2 Plugin lies about its capabilities
**Resolution**: conformance suite (run on first install + opportunistically). Failures quarantine the plugin. The placement engine consults capability flags but verifies dynamically by sampling — e.g., if `supports_delete=true` was declared, GC delete results that consistently come back `not_supported` are flagged. *I8 + I9 preserved.*

#### 2.A.3 Plugin crashes mid-operation
**Resolution**: WASM trap → host isolates → in-flight op fails with `plugin_resource_error` (retryable on a fresh plugin instance). The placement engine treats the plugin as `degraded` and routes new work elsewhere until restart. Existing chunks placed on it remain; scrub detects unhealthy access and triggers repair. *I3 preserved.*

#### 2.A.4 Plugin exceeds rate-limit silently
**Resolution**: plugin's `health()` reports rate-limit state; placement engine respects it. If the plugin lies and the engine sees `provider_error` with retryable=true at high frequency, the engine adapts by lowering effective concurrency for that plugin. *I3 + I8 preserved.*

#### 2.A.5 Plugin returns garbage / corrupted ciphertext
**Resolution**: AEAD tag verification fails on read → shard marked `degraded` → inline read repair → re-place on a different driver → the offending shard becomes a shadow if the bad plugin can't delete it. *I2 + I5 preserved.*

#### 2.A.6 Plugin holds idempotent retries for an inadequate window
**Resolution**: contract requires ≥ 1 hour idempotency dedupe; conformance suite tests for this. If a real plugin breaks idempotency, retries may produce duplicate handles → engine treats them as concurrent puts (see §2.B.3). The wasted handle becomes a shadow. *I5 preserved (with cost).*

#### 2.A.7 Plugin reports `quota_used_bytes` dishonestly
**Resolution**: engine cross-checks via test-puts (very small probe writes) when capacity diverges from prediction. Persistent dishonesty → plugin enters `untrusted_quota` state; placement engine derates its effective capacity. *I9 preserved.*

#### 2.A.8 Plugin disappears (no longer loaded, removed by user)
**Resolution**: chunks placed via that plugin become unreachable on that driver. Engine marks all those shards `LOST` for repair-from-other-replicas. If user re-adds the plugin, engine attempts to re-locate via known handles before deciding LOST. *I3 preserved.*

#### 2.A.9 Plugin updated mid-vault — capabilities change
**Resolution**: a `plugin.capability_changed` event is emitted at load. Placement engine re-evaluates affected chunks and may re-place if requirements no longer match. **New rule**: a plugin that *loses* a capability (e.g., previously claimed `supports_delete=true`, now `false`) cannot be loaded over older state without explicit user confirmation; a plugin that *gains* a capability is hot-loaded freely.

#### 2.A.10 Two different plugins point at the same physical backend (e.g., two Drive accounts containing identical files)
**Resolution**: each plugin instance has a unique `provider_id`. The engine treats them as logically distinct — placement, accounting, and diversity all use `provider_id`. The trust-correlation graph correctly identifies them as the same `trust_correlation_group` (so diversity rule still works). *I3 preserved.*

#### 2.A.11 Plugin honors delete then re-emits the bytes via a public mirror (Imgur thumbnails, archive.org crawl)
**Resolution**: cannot be prevented at the plugin layer. The plugin honestly reports `cached_elsewhere_risk` (low/medium/high). Vault destruction shows residual exposure. **Encryption is the privacy guarantee**; bytes that survive are keyless ciphertext. *I1 preserved structurally; user informed of bytes-elsewhere reality.*

### 2.B — Multi-Device Concurrency

#### 2.B.1 Concurrent updates to the same field of a single FILE record
**Resolution**: `LWW_SET` op kind. HLC ordering picks a winner. Both devices converge after merge. Intra-field concurrent edits don't fragment because each field is its own LWW register.

#### 2.B.2 Concurrent renames (Device A renames /a → /b; Device B renames /a → /c)
**Resolution**: the namespace is modeled as an OR-tree CRDT. A rename is `OR_SET_REMOVE(parent_dir, "a", cause=hlc_A) + OR_SET_ADD(parent_dir, ("b", file_id), cause=hlc_A)`. Concurrent renames produce two add records; HLC picks which is exposed. The losing rename is captured in a `concurrent_rename_history` log surfaced via the API so the user can review. *I6 preserved.*

#### 2.B.3 Concurrent updates to the same chunk content (Case 6 from prior review)
**Resolution**: **the missing fix**. Every `LWW_SET(shard:S.native_handle, …)` op carries a new field `previous_value` containing the handle the writer is replacing.

```
LWW_SET {
  target          : shard:S.native_handle
  value           : H_new
  hlc             : t
  device_id       : D
  previous_value  : H_old   ← required for handle-targeting LWW ops
}
```

On CRDT merge:
- If a remote LWW_SET's `previous_value` matches our locally-pinned current value → standard LWW; no shadow.
- If the remote's `previous_value` does NOT match (we have a different handle that we wrote ourselves) → the locally-pinned value is **demoted**. Emit `OR_SET_ADD(shadows, {handle: locally_pinned_value, reason: concurrent_update_demoted, …})`.

This converts concurrent-update orphans into properly-tracked shadows on whichever device "loses." *I5 preserved.*

#### 2.B.4 Concurrent delete vs. update
Device A deletes file F; Device B updates F at nearly the same moment.
**Resolution**: file existence is itself a CRDT register (`exists ∈ {alive, deleted}`) with HLC. Whichever op has later HLC wins. If delete wins, B's just-uploaded shards become shadows on next merge (via §2.B.3 mechanism — the shard records pointing to B's uploads no longer have a referencing file, refcount → 0, GC cleans up). If update wins, A's logical delete is overridden, the file remains.

#### 2.B.5 Concurrent share creation and file deletion
A creates share for F; B deletes F.
**Resolution**: share creation is `OR_SET_ADD(shares, …)`. File deletion sets `file_F.exists = deleted`. If delete wins → share has scope pointing at a deleted file → engine emits `share.orphaned` event so user can decide; the share blob held by recipient becomes inert (chunks no longer fetchable since refcount → 0).

#### 2.B.6 Concurrent revocation by owner and acceptance by recipient
Owner revokes share, recipient accepts in same window.
**Resolution**: `wrapped_keys[recipient]` is OR-Set-managed; revocation is OR_SET_REMOVE; acceptance is local-side metadata only (no impact on owner's metadata). HLC ordering: if revoke wins, file key already rotated, recipient's wrapped key is invalid for new ciphertext. If accept wins, recipient gets brief access until next revocation cycle.

#### 2.B.7 WAL fork (Device A and Device B both have unsynced WALs that have diverged)
**Resolution**: Merkle anti-entropy detects divergence. Each device replays missing peer ops in HLC order, applying CRDT semantics. Convergence is mathematically guaranteed because all op kinds are commutative+associative+idempotent. *I6 preserved.*

#### 2.B.8 Lease holder crash mid-snapshot
**Resolution**: lease has TTL; expires automatically. Other device may take over. Snapshot upload is atomically pointer-swapped only after verify (DESIGN §6.6); a half-uploaded snapshot is invisible. *I7 preserved.*

#### 2.B.9 Device clock far in the future / past (HLC drift)
**Resolution**: HLC clamps physical time to `max(local_physical, max_seen_remote_physical) + 1` in the logical part. Even with a clock 5 years in the future, ordering is consistent; the logical counter takes over. *I6 preserved.*

#### 2.B.10 Revoked device tries to sync
**Resolution**: every WAL op is signed by the originating device's key. Vault state lists `allowed_devices`. Engines reading from vault verify each op's signature against `allowed_devices`. Revoked-device ops are rejected. The revoked device's local state is not directly destroyed (out of our reach) but its writes don't propagate. *I7 preserved.*

### 2.C — Backend Failures

#### 2.C.1 Single backend slow / unreachable on read
**Resolution**: hedged reads (DESIGN §6.4). Fire K + H requests, take first K. Slow backend doesn't stall reads.

#### 2.C.2 Single backend dies mid-write
**Resolution**: per-shard quorum-write (DESIGN §6.3). Write commits at W acks; the dead backend's shard re-routes via repair scheduler to a healthy driver.

#### 2.C.3 Multiple backends die simultaneously, exceeding (N − K) failures
**Resolution**: the chunk transitions to `LOST`. `chunk.lost` event emitted. User-facing list of affected files. No silent loss. *I4 preserved.*

#### 2.C.4 Vault provider lost (metadata vault)
**Resolution**: vault replication ensures ≥1 other vault provider has the snapshot. Vault Manager promotes a replica. Anti-entropy reconciles any drift. *I7 preserved.*

#### 2.C.5 ALL vault providers lost simultaneously
**Resolution**: catastrophic. Local cache is still authoritative. User must add new vault provider; engine flushes current state to it. If the local cache was also lost in the same incident, recovery falls to the user's recovery materials (Shamir / recovery file / hardware key) → re-bind to fresh vault providers and re-fetch chunks from chunk backends.

#### 2.C.6 Network partition between user's device and all backends
**Resolution**: writes queue locally up to `cache.write_staging_max_bytes`. Reads are served from cache when available. User notified. On reconnect, queued writes flush in HLC order.

#### 2.C.7 Backend is honest but extremely slow (mobile uploading via cellular)
**Resolution**: per-plugin `concurrency_limit` and rate-limit declarations gate parallelism. Bandwidth-aware scheduler (mobile cellular vs. wifi profile). The slow backend doesn't block other backends' progress.

#### 2.C.8 Backend rolls back its state (provider data corruption restores an older copy)
**Resolution**: snapshot pointer is signed with monotonic counter (DESIGN §6.6). Old snapshot has lower counter → engine refuses it. Anti-entropy with other vaults provides cross-check. *I7 preserved.*

#### 2.C.9 Backend serves a different user's bytes by mistake (unlikely but possible)
**Resolution**: AEAD tag mismatch on read → `corrupted` outcome → repair from other replica → the offending shard recorded as unhealthy. *I2 preserved.*

#### 2.C.10 Backend stops being free (free tier ended)
**Resolution**: not a technical failure — a user choice. User disconnects the plugin via API; engine starts `migrate-out` flow for that provider; chunks rebalance.

### 2.D — Storage Leak Scenarios (I5)

#### 2.D.1 Update where backend cannot in-place overwrite
**Resolution**: §2.A.1 — `PutResult.prior_handle_state ∈ {abandoned, tombstoned, unknown}` triggers SHADOW SHARD registration.

#### 2.D.2 Concurrent updates from two devices
**Resolution**: §2.B.3 — `previous_value` field + demotion rule.

#### 2.D.3 Repair-replace where old plugin can't delete
**Resolution**: shadow with `reason=repair_replaced`.

#### 2.D.4 GC delete returns abandoned/unknown
**Resolution**: shadow with `reason=deletion_orphaned`.

#### 2.D.5 Vault destruction with surviving shadows
**Resolution**: residual report (`/v1/vaults/{v}/shadows/destruction-preview`) lists every shadow with `cached_elsewhere_risk` so user knows what bytes remain. Crypto-shred makes them keyless. *I1 preserved.*

#### 2.D.6 Tombstone never clears (plugin promised delete propagation but never delivers)
**Resolution**: opportunistic peek loop; if 3× `delete_propagation_seconds` passes with the object still existing, escalate to permanent shadow. Surfaced via `quota.unreclaimable_growing` event.

#### 2.D.7 Plugin reports `quota_reclaimed=yes` but the bytes still count against quota
**Resolution**: engine reconciles via periodic capacity probe (small test write to detect actual free space). Persistent discrepancy → plugin enters `untrusted_quota` state.

### 2.E — Capacity & Scaling

#### 2.E.1 User adds a new backend to an existing vault
**Resolution**: rebalancer (§3.4) migrates a configurable fraction of existing shards toward the new backend. Throttled, idempotent, resumable. New writes immediately use the new backend per placement-engine logic.

#### 2.E.2 User removes a backend
**Resolution**: `migrate-out` API call. Repair scheduler enqueues all shards on that backend as high-priority. Once 0 active shards remain, plugin can be deleted; existing shadows on it remain in registry until vault destruction.

#### 2.E.3 Backend approaching quota
**Resolution**: pool-aware capacity planner emits `provider.quota_low` event. Placement engine derates that backend in placement weights. User can preemptively add another backend.

#### 2.E.4 EC scheme insufficient as backend pool grows
**Resolution**: dynamic EC selection (§3.2). At each chunk write, select `(k, n)` based on `min(distinct_trust_groups_available, max_practical_n)`. Existing chunks may be re-encoded by the rebalancer if the EC scheme changes meaningfully.

#### 2.E.5 Heterogeneous backend capacities (15 GB Drive + 4 TB NAS)
**Resolution**: capacity-weighted CRUSH placement (§3.3). NAS gets proportionally more shards; small backends not over-filled.

#### 2.E.6 Hot vs. cold data placement inefficiency
**Resolution**: tier classification (§3.5). `access_count_window` drives hot/warm/cold tier; placement engine routes accordingly.

#### 2.E.7 Metadata exceeds per-vault budget
**Resolution**: warning event at 80% of `cache.metadata_max_bytes`. Compression (§3.6) reduces metadata footprint. User can increase chunk size to reduce per-chunk metadata.

### 2.F — Snapshot, Recovery, and Identity

#### 2.F.1 Snapshot pointer rollback attack by malicious vault provider
**Resolution**: signed monotonic counter. Engine refuses pointer with `version_counter ≤ last_seen`. *I7 preserved.*

#### 2.F.2 Identity key rotation
**Resolution**: identity has versioned `epoch_id`. Snapshot pointers include the signing key's `epoch_id`. The recovery manifest stores the chain of identity-pubkey fingerprints, signed by the previous epoch's key. Cold start follows the chain forward to the current valid identity. Lost a chain link → recovery fails honestly.

#### 2.F.3 Lost device, partial WAL not yet flushed
**Resolution**: writes since last WAL flush are lost. The `snapshot.wal_flush_interval` parameter controls the window (default 30 s). For zero-loss, set to write-through mode.

#### 2.F.4 Cold start when both local cache and vault are stale
**Resolution**: anti-entropy with peer devices (if any are online) provides freshest state. If no peer is online and vault is stale, user gets stale view temporarily — peer sync resolves on connect.

#### 2.F.5 Vault format version mismatch on cold start
**Resolution**: format-version migration (DESIGN §15). Online forward migration. Refuse downgrade.

### 2.G — Sharing Edge Cases

#### 2.G.1 Owner offline; recipient cannot fetch chunks
**Resolution**: optional `republisher_hint` in `share_blob`. Recipient can pin shared chunks to their own backends (re-uploading the encrypted ciphertext under their own plugin). Owner sees this via `share.republished` event.

#### 2.G.2 Recipient was previously verified, then their key rotates
**Resolution**: peer record stores their identity. Key rotation invalidates `verified=true` flag (UX prompts re-verification). New identity treated as a new peer until verified.

#### 2.G.3 Share recipient subpoenaed
**Resolution**: out of our hands. Recipient possesses plaintext (they accepted). The threat model already records this (THREAT_MODEL §6.G).

#### 2.G.4 Cyclical share (A shares with B, B shares with C, C shares with A)
**Resolution**: each share is an independent OR-Set entry; no cycle issue at the data layer. UX may surface "you already have access" to avoid duplicate share blobs.

#### 2.G.5 Concurrent share creation race
**Resolution**: shares are OR-Set-managed; concurrent creates produce two share records, both valid.

### 2.H — Plaintext Side-Channels

#### 2.H.1 Chunk hash leaks plaintext fingerprint
The chunk hash is `BLAKE3(plaintext)` for dedup. A vault provider seeing a chunk hash could potentially confirm the user has a specific public file (e.g., a leaked document with a known hash).
**Resolution**: per-vault salt. Engine uses `BLAKE3(per_vault_salt || plaintext)` by default. **Loses cross-vault dedup** but each user's vault is its own dedup domain anyway. Surfaced as a vault config option `chunking.hash_mode = vault_salted | global_blake3`.

#### 2.H.2 File-size fingerprinting via shard count and size
**Resolution**: fixed-size chunks default + chunk packing (when CDC enabled) hide individual file sizes. Aggregate volume still visible — see THREAT_MODEL T-NET-2.

#### 2.H.3 Access-pattern fingerprinting via shard read frequency
**Resolution**: opt-in cover traffic (out of scope for default operation). Documented as residual.

### 2.I — Plugin Sandbox Edge Cases (I8)

#### 2.I.1 Plugin attempts memory exhaustion
**Resolution**: WASM heap limit (default 256 MiB, max 1 GiB). Exceeded → terminate plugin call with `plugin_resource_error`.

#### 2.I.2 Plugin attempts CPU exhaustion (infinite loop)
**Resolution**: per-call execution timeout (default 60 s). Trap on overrun.

#### 2.I.3 Plugin tries to contact non-allowlisted host
**Resolution**: blocked at the sandbox boundary. `network_violation` logged; plugin call fails.

#### 2.I.4 Plugin abuses signed_fetch within allowlisted hosts to attack the user's account
**Resolution**: per-plugin rate-limit caps. Abuse triggers `provider.quarantined` → plugin disabled until user investigates.

#### 2.I.5 Sandbox escape via WASM runtime bug
**Resolution**: residual risk acknowledged in THREAT_MODEL. Mitigated by hardened runtime selection + rapid security updates. *I8 partially preserved; user notified of risk class.*

---

## 3. The Strengthening Designs

These are the new architectural pieces required to make the invariants robust under any plugin behavior. Cross-referenced from §2 above.

### 3.1 CRDT Op Vocabulary (final)

Every WAL entry uses one of these op kinds. The engine knows how to merge each.

| Op kind | Semantics | Used for |
|---|---|---|
| `LWW_SET` | Last-writer-wins register; carries `previous_value`. | Scalar fields (file size, mtime, single-valued metadata, native_handle) |
| `OR_SET_ADD` | Observed-remove set add; carries `add_id`. | Adding to lists (recipients, devices, shadows, peers, shares) |
| `OR_SET_REMOVE` | Observed-remove set remove; carries `add_id` reference. | Removing from lists; revocation |
| `COUNTER_INC` | Monotonic counter increment. | Refcount, access count |
| `MAP_PUT` | Add/update key in map. | Sharded metadata maps (per-driver state) |
| `MAP_DEL` | Remove key from map; carries `add_id`. | Map removal |
| `PATH_MOVE` | Atomic rename: REMOVE + ADD with linked cause. | File / directory rename |
| `LWW_REGISTER` | Single-value register without previous_value (for fields that don't need shadow demotion). | Mode bits, content type, etc. |

`LWW_SET` (with `previous_value`) is mandatory for fields whose old values represent placed ciphertext (handle, driver_id). All other CRDT ops follow standard semantics.

### 3.2 Dynamic EC Selection

```
At each chunk write:
  available_groups = distinct trust-correlation groups in healthy plugin pool
  N_max            = max practical (capped by config; default 13)
  K_target         = config.redundancy.k (default 4)
  N_chosen         = min(available_groups, N_max)
  if N_chosen < K_target + 1:
    fall back to replication mode (replication_factor = available_groups)
  else:
    EC scheme = (K_target, N_chosen)
```

The EC scheme is recorded per-chunk; mixed schemes coexist. The rebalancer (§3.4) may re-encode chunks if their scheme is significantly suboptimal vs. current pool.

### 3.3 CRUSH-Style Capacity-Weighted Placement

```
For chunk hash H, shard index i, target plugin pool P:
  weights = { p.id: f(p.remaining_quota, p.health, p.tier_match, p.weight) for p in P }
  candidate = consistent_hash(H || i, weights)
  enforce diversity: if candidate's trust_group already used for prior shards
    of this chunk, pick next-best per consistent-hash ordering
  return candidate
```

Properties:
- Deterministic: same hash + same pool → same placement.
- Stable under topology change: adding/removing a plugin re-places only ~1/N of chunks.
- Capacity-aware: backends with more remaining space get proportionally more shards.

Exact algorithm: a variant of [CRUSH](https://ceph.io/assets/pdfs/weil-crush-sc06.pdf) (Weil et al., 2006), simplified to a single-level hierarchy (no rack / row, just trust groups).

### 3.4 Rebalancer

```
Triggers:
  - plugin added → migrate fraction toward new
  - plugin removed (migrate-out) → drain
  - plugin capacity-changed → re-weight
  - dynamic EC scheme suggests re-encode for cold chunks
  - tier reclassification (hot ↔ cold)

Behavior:
  - bounded throughput (config.rebalancer.bandwidth_cap)
  - resumable across engine restarts (state in metadata)
  - throttled by repair scheduler's rate-limit budget
  - chunks selected by priority: oldest-mismatch first
```

### 3.5 Tier Classification

```
For each chunk, derive tier from access_count_window:
  hot     : accessed > N_h times in last 7 d
  warm    : accessed 1–N_h times in 7 d
  cold    : not accessed in > 30 d

Per-tier policy:
  hot     : K=4, N=7, prefer fast/clean backends, narrow EC for fast read
  warm    : K=4, N=7, default placement
  cold    : K=8, N=12, prefer cheap/slow backends, wide EC for storage savings
```

The rebalancer migrates chunks across tiers when their classification changes.

### 3.6 Metadata Compression

zstd with a per-vault trained dictionary. Dictionary version recorded in vault metadata. On compaction, samples ~1% of metadata pages, retrains, compresses. Saves ~30–50% on metadata at scale.

### 3.7 Pool-Aware Capacity Planner

```
Reports:
  - usable_storage = sum(plugin.remaining_quota * (K/N)) - reserved_for_metadata
  - projected_full_at = extrapolate from recent fill rate
  - per-plugin contribution
  - shadow byte share

Surfaces via:
  GET /v1/vaults/{v}/capacity/projection
  Event: capacity.projection_updated (when projection changes by >1 day)
  Event: capacity.threshold_warning (when projected_full_at < 14 days)
```

### 3.8 Identity Signature Chain

```
Identity epochs:
  epoch_0 = original identity at vault creation
  epoch_n = current identity, signed by epoch_{n-1}'s key

Recovery manifest stores:
  identity_chain = [
    { epoch: 0, sign_pubkey: …, kem_pubkey: …, fingerprint: … },
    { epoch: 1, sign_pubkey: …, kem_pubkey: …, signed_by_epoch_0: <sig> },
    …
  ]

Snapshot pointer signature includes epoch_id.
Cold start verifies the chain forward; rejects if a link is missing.
```

### 3.9 Plaintext Hash Salting Mode

Per-vault config:
- `chunking.hash_mode = vault_salted` (default for new vaults): chunk hash = `BLAKE3(per_vault_salt || plaintext)`.
- `chunking.hash_mode = global_blake3`: chunk hash = `BLAKE3(plaintext)` (legacy / cross-vault dedup).

Vault salt is derived from MK under `kp:vault-salt`. Same vault on different devices uses same salt.

### 3.10 Plugin Capability Drift Handling

```
On plugin load:
  compare manifest.capabilities to last_known_capabilities
  if any capability LOST that affects placed chunks:
    require user confirmation to load
    OR enqueue affected chunks for rebalance to other plugins
  if capabilities GAINED:
    hot-load; future placements may use new capabilities

Event: plugin.capability_changed { plugin_id, gained, lost }
```

### 3.11 Untrusted-Quota Mode

When a plugin's reported `quota_used` repeatedly diverges from observed write success:
- Plugin marked `untrusted_quota`.
- Effective capacity for placement decisions = derated estimate from probes.
- Surfaced to user via `provider.quota_untrusted` event.

### 3.12 Network-Partitioned Write Queue

Local staging buffer up to `cache.write_staging_max_bytes`. Writes are durable in local WAL even before plugin acks. On reconnect, queued writes flush in HLC order, idempotently per `idempotency_key`.

---

## 4. The Updated Failure Mode Catalog

| Mode | Detection | Resolution | Invariant preserved |
|---|---|---|---|
| Plugin returns new handle | `PutResult.handle_changed=true` | Shadow registry, metadata update | I5 |
| Plugin claims delete works but doesn't | Conformance suite or post-hoc peek | Plugin → `untrusted` state, shadow recorded | I9, I5 |
| Plugin crashes | WASM trap | Failover to alternate driver; repair affected chunks | I3, I8 |
| Plugin returns corrupted ciphertext | AEAD verify fail | Read repair from other replica | I2, I3 |
| Plugin removed by user | Engine load-time check | Mark all shards LOST; user notified | I3, I4 |
| Concurrent multi-device update | CRDT merge with `previous_value` | Demoted handle → shadow | I5, I6 |
| Concurrent rename | OR-tree CRDT | HLC tiebreak; history retained | I6 |
| Concurrent delete vs update | LWW on `exists` flag | Higher-HLC op wins; orphans shadowed | I5, I6 |
| Vault provider rollback | Signed monotonic counter | Reject; promote replica | I7 |
| All vault providers lost | Vault Manager error | Recovery materials → re-bind | (catastrophe path) |
| Network partition | Loss of plugin connectivity | Local queue; flush on reconnect | (availability degrades; data preserved) |
| Backend ban | Plugin auth error | Quarantine plugin; mass-repair | I3 |
| Backend tombstone never clears | Peek-loop timeout | Permanent shadow | I5, I9 |
| Plugin lies about quota | Probe divergence | Untrusted-quota state | I9 |
| Identity key rotation | New epoch in WAL | Signature chain validated | I7 |
| Plugin gains/loses capability | `capability_changed` event | Re-evaluate placement; rebalance if needed | I3 |
| Sandbox escape (WASM bug) | Out-of-band detection | Hardened runtime + updates | I8 (residual) |
| Cross-vault hash side-channel | n/a (always present) | Per-vault salt mode | I1 (privacy improvement) |
| Compromised endpoint with vault unlocked | Out of scope | n/a | (residual; THREAT_MODEL T-LD-1) |

---

## 5. Plugin Authoring: How To Be A Well-Behaved Citizen

If a plugin author wants their plugin to fully exploit the core's strength:

### 5.1 Honest Declarations
Always declare exactly what the backend does. Lying about `supports_delete`, `update_in_place`, `delete_reclaims_quota`, or `cached_elsewhere_risk` is the single most damaging plugin behavior. **Honest "no" is always better than dishonest "yes."**

### 5.2 Idempotency
Implement at least the contract minimum (1-hour dedupe by `idempotency_key`). Use the backend's own idempotency primitive when available (most cloud APIs support it).

### 5.3 Honest `health()`
Report real numbers. If you don't know quota, report `quota_total=null`. If rate limits are dynamic, report current state.

### 5.4 Capability Stability
Don't change declared capabilities silently between versions. Use the manifest's `plugin_version` to convey changes; users get an explicit upgrade path.

### 5.5 Tolerate Repeated Writes
Same payload + same `idempotency_key` should always yield same handle. Same payload + different keys may legitimately produce different handles.

### 5.6 Honest Error Codes
Map your provider's errors to the canonical codes (`PLUGIN_SDK.md` §9). Don't map everything to `provider_error` — the engine plans badly without specificity.

### 5.7 Cooperate with Anti-Entropy
For plugins also serving the `metadata_vault` role: implement `cas_write` correctly. CAS is the foundation of lease coordination and snapshot pointer atomicity.

---

## 6. The Strong Core, Restated

After all of the above, the core promises this to a plugin author and to the user:

- **A plugin can fail in any way the contract allows. The user's data survives.**
- **A backend can be hostile, immutable, append-only, or lose data silently. The user's data is reconstructable from elsewhere or is honestly reported as lost.**
- **The user's bytes never leave their device unencrypted. Period.**
- **Every byte placed somewhere is either referenced, shadowed, or honestly reported as outside our control. There are no silent leaks.**
- **Every device the user owns converges to the same view, deterministically, regardless of order or timing of merges.**
- **Adding a new plugin grows storage. Removing one shrinks it predictably. The system explains how much of each.**

That's the core. Plugins implement five operations. The core does the rest.
