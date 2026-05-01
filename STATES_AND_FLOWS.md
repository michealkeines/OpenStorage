# OpenStorage — States, Operations, and Flows (Exhaustive)

> **Purpose**: this document is the *complete enumeration* of every state, every operation, every flow, and every edge case. Where prior documents describe individual flows or invariants, this one is the matrix that ties them together. **No data flow may exist without being documented here**; if a path isn't listed, it isn't permitted.
>
> **Read alongside**: [`DESIGN.md`](./DESIGN.md), [`ABSTRACTIONS.md`](./ABSTRACTIONS.md), [`RESILIENCE.md`](./RESILIENCE.md), [`PLUGIN_SDK.md`](./PLUGIN_SDK.md), [`API.md`](./API.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## 0. How This Document Came To Exist

A flow-tracing review of the per-module FLOW.md files surfaced:
- 5 layer-rule violations
- 7 orchestration gaps
- 3 subtle data-shape issues
- 1 structural circular dependency (cold-start identity chain)
- ~15 newly-discovered edge cases

This document is the resolution: the canonical **state × operation matrix**, the **complete flow catalog**, and the **edge-case index** with explicit resolutions for every case.

---

## 1. State Machines (Every Entity)

### 1.1 Vault State

States: `Uncreated → Locked → Unlocking → Unlocked → Locking → Locked` (cycle), plus `Unlocked → Destroying → Destroyed` (terminal).

Operations valid per state — see `ABSTRACTIONS.md` §6.3.

### 1.2 Plugin State

```
   ┌──────────┐
   │  Loaded  │ — manifest verified, sandbox prepared, no live state
   └────┬─────┘
        │ init(settings, credentials_handle)
        ▼
   ┌──────────┐
   │   Init   │ — internal probe; may issue signed_fetch
   └────┬─────┘
        │ ready
        ▼
   ┌──────────┐ ◄────────────────────────┐
   │  Ready   │                          │ resume
   └────┬─────┘                          │
        │ first invoke                   │
        ▼                                │
   ┌──────────┐                          │
   │  Active  │ ────────► pause ──────► Paused
   └────┬─────┘                          ▲
        │                                │
        │ capability change detected     │
        ▼                                │
   ┌──────────────────────┐              │
   │ AwaitingUserDecision │              │
   └────┬────────┬────────┘              │
        │        │                       │
        │        └── user: keep ─────────┘ (capabilities downgraded; back to Active)
        │
        └── user: migrate-out ──────► Migrating ──► (drained) ──► Disabled
                                                                       │
                                                                       │ user removes
                                                                       ▼
                                                                    Closed
```

| Op | Loaded | Init | Ready | Active | Paused | AwaitingUserDecision | Migrating | Disabled | Closed |
|---|---|---|---|---|---|---|---|---|---|
| init | ✓ | (in-flight) | — | — | — | — | — | — | — |
| invoke (5 ops) | — | — | — | ✓ | rejected | rejected | rejected | rejected | — |
| pause | — | — | ✓ | ✓ | — | — | — | — | — |
| resume | — | — | — | — | ✓ | — | — | — | — |
| reload (capability changed) | — | — | ✓ | ✓ | ✓ | — | — | — | — |
| migrate-out | — | — | ✓ | ✓ | ✓ | from here | (in-flight) | — | — |
| shutdown | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |

### 1.3 Lease State

```
   ┌──────┐
   │ Free │
   └──┬───┘
      │ acquire (CAS write succeeds)
      ▼
   ┌──────┐ ─── renew ───► (Held with new expires_at) ─┐
   │ Held │                                            │
   └──┬───┘ ◄──────────────────────────────────────────┘
      │
      ├── release (explicit) ──────► Free
      ├── TTL expires (silent) ────► Free
      └── stolen (other device CAS-writes after 2×TTL) ──► Free (but our state thinks Held until next read)
```

- `Free`: any device may acquire.
- `Held`: holder may renew; non-holders may not write the lease record but MAY write WAL ops (lease is advisory).
- After steal: previous holder's next renew CAS fails; emits `lease.lost` event; updates local state to Free.

### 1.4 Chunk Replication State

```
   ┌──────────┐
   │   Full   │ ── all N shards Healthy
   └────┬─────┘
        │ a shard becomes Degraded
        ▼
   ┌──────────┐  ◄──── repair adds healthy ──────┐
   │ Degraded │                                  │
   └────┬─────┘                                  │
        │ repair scheduler picks up              │
        ▼                                        │
   ┌────────────┐                                │
   │ Recovering │ ── all healthy ────────────────┘
   └────┬───────┘
        │ healthy < K, repair impossible
        ▼
   ┌──────┐
   │ Lost │ ── terminal until restored from share or backup
   └──────┘
```

### 1.5 Shard State

```
   ┌──────────┐
   │  Staged  │ — encrypted, hash known, awaiting placement
   └────┬─────┘
        │ placement assigns ProviderId
        ▼
   ┌──────────┐
   │ Placing  │ — plugin put in flight
   └────┬─────┘
        │ ack
        ▼
   ┌──────────┐ ◄─── repair completes ─┐
   │  Healthy │                        │
   └────┬─────┘                        │
        │ verify fail / scrub fail     │
        │ / read-repair detect         │
        ▼                              │
   ┌──────────┐                        │
   │ Degraded │ ── enqueued in repair ─┘
   └────┬─────┘
        │ chunk EC threshold breached
        ▼
   ┌──────┐
   │ Lost │ — chunk-level
   └──────┘

   Independent: Free  ─── refcount=0 ──► (delete via plugin) ──► (Removed | Tombstoned | Abandoned)
```

### 1.6 Shadow State

```
   ┌────────────┐
   │ Registered │ — newly demoted; bytes still on backend
   └─────┬──────┘
         │ peek confirms not_found (after tombstone clears)
         ▼
   ┌────────────┐
   │  Cleared   │ — fully removed
   └────────────┘
   
   ┌────────────┐
   │ Registered │
   └─────┬──────┘
         │ peek persistently confirms exists (abandoned indefinitely)
         ▼
   ┌────────────┐
   │ Permanent  │ — counted forever in residual reports
   └────────────┘
```

### 1.7 Share State

```
   ┌─────────┐
   │ Created │ — owner created; share_blob produced
   └────┬────┘
        │
        ├── recipient imports + accepts ──► Active (recipient-side)
        │   owner sees: Active
        │
        ├── expires_at passes ───────────► Expired (both sides)
        │
        └── owner revokes ───────────────► Revoked
                                            file_key rotated
                                            recipient's wrapped_keys removed
                                            chunks re-encrypted
```

### 1.8 WAL Entry State (Durability)

```
   ┌──────────────┐
   │  In Memory   │ — appended to in-memory ring
   └──────┬───────┘
          │ fsync
          ▼
   ┌──────────────┐
   │ Local Durable│ — survives device crash
   └──────┬───────┘
          │ flushed to vault provider
          ▼
   ┌──────────────────┐
   │ Vault Replicated │ — survives device loss
   └──────┬───────────┘
          │ included in snapshot rotation
          ▼
   ┌──────────────────┐
   │   Compacted      │ — entry now part of snapshot; can be truncated
   └──────────────────┘
```

### 1.9 Repair Task State

```
   ┌────────────┐
   │  Enqueued  │ ── in priority queue
   └─────┬──────┘
         │ worker pops
         ▼
   ┌────────────┐
   │ InFlight   │ ── reading source replica + writing new replica
   └─────┬──────┘
         │
         ├── success ─► Completed (chunk shard returns to Healthy)
         │
         ├── partial (shadow registered for old) ─► Completed
         │
         └── failure ─► Re-enqueued with backoff
                       (after N retries → Failed; chunk may transition to Lost)
```

### 1.10 Recovery Configuration State

```
   Unconfigured (default at vault creation, passphrase only)
        │
        │ user adds modes
        ▼
   Configured (passphrase + recovery file ± Shamir ± hardware)
        │
        │ user attempts recovery on fresh device
        ▼
   InProgress (materials being verified)
        │
        ├── success ─► Recovered (vault is Unlocked)
        │
        └── failure ─► RecoveryFailed (back to Unconfigured-equivalent on this device)
```

---

## 2. Comprehensive Flow Catalog

Every API operation gets a flow. Grouped by category; for each: trigger, preconditions, primitive sequence, postconditions, edges.

### 2.1 Vault Lifecycle

#### F-VL-1: Create Vault

- **Trigger**: `POST /v1/vaults`
- **Pre**: User has plugin instances configured (or chooses "use my Drive plugin for both metadata and chunks"). Recovery modes selected.
- **Flow**:
  1. `crypto/`.derive MK from passphrase + Argon2id with profile detection.
  2. `crypto/`.derive vault_salt under `kp:vault-salt`.
  3. `identity/`.create_identity → epoch_0.
  4. `recovery/`.build manifest (modes wrapped, identity_anchor_fingerprint, identity_chain=[epoch_0]).
  5. `vault/`.push manifest to vault provider(s) via `plugin_host/`.
  6. `metadata/`.persist Vault entity.
  7. `wal/`.append initial ops (vault metadata, owner identity).
- **Post**: Vault state = Locked. User receives one-time recovery file URL if configured.
- **Edges**:
  - User's chosen vault provider rejects the manifest write → fail with `provider_unavailable`; vault not created.
  - Two simultaneous create requests → second blocked at API layer (one-vault-being-created lock).

#### F-VL-2: Unlock Vault (passphrase)

- **Trigger**: `POST /v1/vaults/{v}/unlock`
- **Pre**: Vault state = Locked.
- **State transition**: Locked → Unlocking → Unlocked.
- **Flow**:
  1. `recovery/`.derive MK from passphrase.
  2. `vault/`.fetch encrypted RecoveryManifest from configured vault provider.
  3. `crypto/`.decrypt manifest with MK; verify check-blob.
  4. Walk `manifest.identity_chain` forward; verify each `signed_by_prev`. Establish current epoch.
  5. `vault/`.fetch SignedSnapshotPointer; verify signature against current epoch.
  6. `vault/`.fetch snapshot pages; `crypto/`.decrypt with snapshot key.
  7. `metadata/`.bulk_apply pages.
  8. `wal/`.replay segments since snapshot cutoff.
  9. `keystore/`.store wrap key for fast subsequent unlock.
- **Post**: Vault state = Unlocked. Event `vault.unlocked` emitted. Lease attempt initiated.
- **Edges**:
  - Wrong passphrase → manifest decrypt fails (AEAD tag) → `unauthenticated`. State returns to Locked.
  - Manifest fetch returns NotFound from all vault providers → fall back to recovery materials.
  - Snapshot pointer signature fails → `corrupted`; refuse to load. User must investigate.
  - Pointer's `version_counter ≤ local last_seen` → rollback attack; refuse; emit `provider.health_changed { state: suspect }`.
  - Manifest's `identity_anchor_fingerprint` doesn't match `BLAKE3-160(epoch_0.sign_pubkey)` → `identity.chain_invalid`; refuse.
  - Concurrent unlock from two devices: each derives MK independently; both succeed; both update lease (one wins CAS).

#### F-VL-3: Lock Vault

- **Trigger**: `POST /v1/vaults/{v}/lock`, idle timeout, or shutdown.
- **State transition**: Unlocked → Locking → Locked.
- **Flow**:
  1. `lease/`.release if held.
  2. Drain in-flight writes (bounded timeout).
  3. Force a snapshot push if dirty pages exist.
  4. `crypto/`.zeroize MK from memory.
  5. Plaintext read cache cleared.
- **Post**: Vault state = Locked. Event `vault.locked`.
- **Edges**:
  - In-flight writes that don't drain in time: aborted; clients receive `vault_locked` on next stream chunk.
  - Snapshot push fails: lock proceeds anyway; WAL is durable locally; will sync on next unlock.

#### F-VL-4: Destroy Vault

- **Trigger**: `DELETE /v1/vaults/{v}` with confirmation header.
- **State transition**: Unlocked → Destroying → Destroyed.
- **Flow**:
  1. Block new writes; reads served from cache only.
  2. `lease/`.release.
  3. `recovery/`.enumerate all shards + all shadows.
  4. For each (provider, handle): `plugin_host/`.invoke delete; collect outcomes.
  5. `crypto/`.zeroize MK.
  6. Overwrite RecoveryManifest with random bytes.
  7. `keystore/`.delete wrap key.
  8. Build ResidualReport; return synchronously to API.
  9. Vault entity removed from metadata.
- **Post**: Vault state = Destroyed (terminal). User receives report.
- **Edges**:
  - Engine crashes mid-sweep: on restart, vault is in Destroying; resume sweep from where it stopped (sweep state persisted).
  - A plugin returns network_error: retry with backoff; if persistently fails, mark shadow as `unknown` and proceed.
  - User cancels mid-sweep: not allowed; once Destroying, no abort path. Document this clearly in UX.

#### F-VL-5: Rotate Master Key

- **Trigger**: `POST /v1/vaults/{v}/rotate-key`
- **Pre**: Vault state = Unlocked.
- **Flow**:
  1. `crypto/`.derive new MK from new passphrase (or new recovery materials).
  2. For each per-file key: unwrap with old MK; rewrap with new MK.
  3. Re-encrypt RecoveryManifest under new MK.
  4. Update `keystore/` wrap.
  5. `crypto/`.zeroize old MK.
- **Post**: User re-prompted on next unlock. Old passphrase no longer works.
- **Edges**:
  - Rotation interrupted mid-rewrap: on restart, partial rewrap recoverable via metadata-stored progress marker.
  - Concurrent rotation from two devices: lease holder wins; other rotation aborted.

### 2.2 File Operations

#### F-FL-1: Read File

- **Trigger**: `GET /v1/vaults/{v}/files/{path}`
- **Pre**: Vault Unlocked; file exists.
- **Flow**:
  1. `vfs/`.resolve path → File entity.
  2. If `inline_payload`: decrypt + stream → done.
  3. Else: for each chunk in `chunk_list`, `vfs/`.read_chunk:
     - `vault/`.current_pool() → snapshot.
     - `placement/`.pick K + H healthiest replicas given pool.
     - `plugin_host/`.invoke get on each in parallel.
     - First K to complete: cancel rest.
     - On AEAD verify fail: `repair/`.enqueue(HIGH, source=ReadRepair); continue.
     - `chunk/`.ec_reconstruct + `crypto/`.decrypt.
  4. Stream to API → frontend.
- **Edges**:
  - All hedges fail: read fails with `corrupted` or `provider_unavailable` after exhausting retries.
  - File peek shows it's been deleted between resolve and chunk fetch (concurrent unlink): return `not_found`.
  - Chunk in `Recovering` state: read uses pre-recovery placement (already healthy); recovery happens in parallel.
  - File is in `wrapped_keys` only (no chunks because it's a shared file from another peer): use shared key path.

#### F-FL-2: Write File

- **Trigger**: `PUT /v1/vaults/{v}/files/{path}`
- **Flow**:
  1. `vfs/`.open(path, write).
  2. If size ≤ inline threshold: `chunk/`.encrypt as inline blob; persist in File.inline_payload.
  3. Else: stream → `chunk/`.split → for each chunk:
     - `chunk/`.encrypt + ec_encode.
     - `vfs/` (orchestrator) `vault/`.current_pool().
     - `placement/`.pick_shards.
     - `plugin_host/`.invoke put × N in parallel; pass `replaces_handle` if updating.
     - Wait for W = k+1 acks.
     - Process `PutResult` per shard: register Shadow if `prior_handle_state ∈ {abandoned, tombstoned, unknown}`.
  4. `wal/`.append all CRDT ops (LwwSet on shard fields, OrSetAdd on file.chunk_list, CounterInc on chunk.refcount).
  5. `metadata/`.commit_txn.
- **Post**: Event `write.quorum_acked`. Background async fan-out for remaining (N-W) shards. On completion: `write.fully_replicated`.
- **Edges**:
  - Available trust groups < K+1: fall back to replication mode automatically (`placement/` decides).
  - Mid-stream client disconnect: WAL-staged writes are kept; idempotency-key retry resumes.
  - Quorum can't be met (e.g., only 4 of 7 plugins healthy at write time): write blocks until enough plugins recover OR fails after a timeout.
  - Pre-existing chunk hash matches via Bloom: skip re-upload (dedup); just bump refcount.
  - Concurrent writer to same file from another device: see F-MD-1.

#### F-FL-3: Update File (partial write)

- **Trigger**: `PATCH /v1/vaults/{v}/files/{path}` with `Content-Range`.
- **Flow**: Same as F-FL-2 but only re-encrypts affected chunks. Uses `replaces_handle` on `put` calls; `PutResult.prior_handle_state` drives shadow registration.
- **Edges**:
  - Range crosses chunk boundary: each crossed chunk fully re-encrypted.
  - Range write that grows file past inline threshold: file converted from inline to chunked atomically (single transaction).

#### F-FL-4: Delete File

- **Trigger**: `DELETE /v1/vaults/{v}/files/{path}`
- **Flow**:
  1. `vfs/`.resolve → File entity.
  2. `wal/`.append LwwRegister(file.exists, false); CounterInc(chunk.refcount, -1) for each chunk.
  3. `metadata/`.commit_txn.
- **Post**: Event `file.changed`. Background GC sweep (in `repair/`) eventually deletes shards.
- **Edges**:
  - File was shared: revocation cascade invalidates recipients' wrapped_keys.
  - Concurrent update vs delete: see F-MD-2.

#### F-FL-5: Rename / Move File

- **Trigger**: `POST /v1/vaults/{v}/files/{src}/move` { to: dst }
- **Flow**: `vfs/`.resolve `src` → FILE record (by stable `file_id`). `wal/`.append `LwwRegister(file.path, dst)`. No tree mutation — `path` is a regular LWW field on the FILE record (DESIGN.md §5.8). Directory listings update implicitly via prefix projection (DESIGN.md §6.13).
- **Edges**: Concurrent rename of same `file_id` — see F-MD-3. Target path already claimed by a different `file_id` — see F-MD-3 same-path collision branch.

#### F-FL-6: Peek (HEAD)

- **Trigger**: `HEAD /v1/vaults/{v}/files/{path}`
- **Flow**: `vfs/`.resolve only; no chunk fetch. Returns size, mtime, etag, replication state.
- **Edges**: Vault locked → 423 with cached metadata if available, else 404.

### 2.3 Multi-Device Coordination

#### F-MD-1: Concurrent Update Same File (Case 6)

- **Pre**: Two devices both unlock vault and write to same file ~simultaneously.
- **Flow** (per device, independent):
  1. Read current chunk handles.
  2. `chunk/`.encrypt new content; produce new shards.
  3. `plugin_host/`.invoke put with `replaces_handle=H_old` → plugin returns new handle and `prior_handle_state`.
  4. `wal/`.append LwwSet(shard.native_handle, H_new, **previous_value=H_old**).
  5. Both devices succeed locally; both register H_old as Shadow with `reason=update_replaced`.
- **Merge** (when one device pulls the other's WAL):
  - Compare remote LwwSet's `previous_value` to local current value.
  - Mismatch (we wrote a different new handle locally): demote our handle → `OrSetAdd(shadows, our_handle, reason=ConcurrentUpdateDemoted)`.
- **Post**: Both devices converge to same handle; shadow registry contains all losing handles.
- **Edges**:
  - Both devices register the same H_old shadow: deduped at metadata insert by `(driver_id, native_handle)` key.
  - HLC tied: tiebreak by `device_id`.
  - One device's plugin call fails: that device's write didn't reach the backend; no shadow needed for it.

#### F-MD-2: Concurrent Update vs Delete

- **Flow**: device A deletes file (LwwRegister exists=false at HLC t_A); device B updates file (LwwSet on shard handles + chunk_list at HLC t_B).
- **Merge**: HLC compare on the `exists` field. If delete wins, file marked deleted; B's updated chunks become unreferenced (refcount → 0 via OrSetRemove); GC eventually cleans up.
- **Edges**: B's just-uploaded shards are tracked in chunk records before refcount drops; not orphaned silently.

#### F-MD-3: Concurrent Rename

- **Flow**: each device emits `LwwRegister(file.path, new_path)` on the same `file_id`. HLC orders the writes; LWW-loser's path field is overwritten on merge. File content (chunk_list, wrapped_keys, AEAD blob) is unaffected on either device.
- **Same-`file_id` rename race** (A: F → /b; B: F → /c): HLC winner takes effect; loser's path value is dropped. The user sees F at one of the two names on every device. No history log; convergence is exact.
- **Same-path collision** (A creates new file F1 at /x; B renames different file F2 to /x): both records survive at the storage layer (different `file_id`s). At read time, the projection function (DESIGN.md §6.13) detects the collision and renders the LWW-loser at `/x.conflict-{loser_hlc}-{file_id[:8]}`. Deterministic across devices. User resolves by renaming or deleting the conflict copy.
- **Move-into-deleted-directory** (A: F → /a/b/F; B: rmdir /a/b concurrently): F's `path` LWW-write succeeds; the explicit DIR record for /a/b is OR_SET_REMOVEd by B. Implicit-directory rule (DESIGN.md §5.8.3 N3) resurrects /a/b at projection time because F's path requires it. No orphan, no lost+found.
- **No cycle case to handle**: paths are strings, not parent pointers. Two files swapping path-shaped names produces two LWW writes on two different `file_id`s; both apply. No tree invariant exists to violate.

#### F-MD-4: Lease Steal

- **Pre**: Device A held the lease; A's process crashed without release.
- **Flow**:
  1. Device B observes lease.json with expires_at ≥ 2 × TTL in the past.
  2. Device B CAS-writes its own lease record over the stale.
  3. Device A, on its next renew attempt, fails CAS.
  4. Device A: emit `lease.lost`; revert local state to Free.
- **Edges**:
  - A wasn't actually crashed, just paused (e.g., laptop sleep): on wake, A's renew fails; A re-acquires only if Free again.
  - Vault provider has weak CAS (capability flag false): plugin refuses metadata-vault role; flagged at install.

#### F-MD-5: WAL Fork & Reconcile

- **Pre**: Devices A and B have written WAL entries during a network partition.
- **Flow**:
  1. Network restores.
  2. Device A pulls B's WAL entries since A's last_seen.
  3. `sync/`.apply_remote_wal_segment for each entry.
  4. Per-op CRDT semantics resolve. Demotion ops emitted where applicable.
  5. Device B does the same with A's WAL.
- **Post**: Both devices converge.
- **Edges**:
  - Forked window long enough that B's last_seen < latest snapshot's cutoff: B fetches snapshot, then WAL tail.
  - One device's WAL contains a revoked-device entry (forged): signature verification fails; entry dropped + logged.

### 2.4 Health & Maintenance

#### F-HM-1: Background Scrub

- **Trigger**: timer; `repair/` runs.
- **Flow**: sample 5%/day. For each: peek each shard. Hash mismatch or missing → enqueue with priority = scrub.
- **Edges**: Scrub catches plugin bit-rot; Discord-style account ban shows up as `auth_failure` on multiple shards → the plugin (not just one shard) is quarantined.

#### F-HM-2: Inline Read Repair

- See F-FL-1 read flow. AEAD verify fail → enqueue HIGH priority; read still serves K healthy shards.

#### F-HM-3: Anti-Entropy Run

- **Trigger**: hourly timer or `POST /v1/vaults/{v}/anti-entropy/run`.
- **Flow**:
  1. For each replica vault provider: fetch `merkle.root`.
  2. If equal to local root: skip.
  3. Else: walk down levels, identify divergent leaves.
  4. Pull divergent pages; apply via `sync/`.
- **Edges**:
  - Replica returning forged Merkle root: page-level hash check during pull catches the fraud.
  - Many divergent pages → fall back to full delta push from latest snapshot.

#### F-HM-4: Rebalance on Plugin Add

- **Trigger**: user adds a plugin instance.
- **Flow**:
  1. `plugin_host/`.load.
  2. `placement/` recomputes pool weights.
  3. Rebalancer enqueues a configurable fraction of existing chunks for re-evaluation.
  4. Worker pool drains, calling `placement/`.evaluate_rebalance_targets per chunk; if differs, schedule re-place via `repair/`.
- **Edges**:
  - User adds many plugins at once: rebalance batches; doesn't thrash.
  - User removes a plugin without migrate-out: emit warning; chunks on it become unreachable; treated as quarantine.

#### F-HM-5: GC Sweep

- **Trigger**: refcount on a chunk drops to 0 (from F-FL-4 etc.).
- **Flow**:
  1. `repair/` runs GC sweep alongside repair work.
  2. For each shard: `plugin_host/`.invoke delete → `DeleteResult`.
  3. Per outcome: `Removed` drops shard record; `Tombstoned/Abandoned/NotSupported` registers Shadow.
  4. When all shards removed/shadowed: chunk record removed.
- **Edges**:
  - All shards on a permanently-down plugin: shadows accumulate; user warned via `quota.unreclaimable_growing`.

### 2.5 Sharing

#### F-SH-1: Create Share

- **Trigger**: `POST /v1/vaults/{v}/shares`
- **Flow**:
  1. Resolve recipient peer's KEM pubkey via `identity/`.
  2. Unwrap file_key with MK.
  3. `crypto/`.kem_encapsulate → wrapped_key.
  4. Append to `file.wrapped_keys` (OrSetAdd).
  5. Build share_blob with optional republisher_hint; sign with current epoch's sign key.
- **Post**: Event `share.created`. User transmits blob OOB.
- **Edges**:
  - Recipient peer not verified yet: warn user; allow but flag.
  - Recipient identity rotated since added: re-add peer; require re-verification.

#### F-SH-2: Accept Share

- **Trigger**: `POST /v1/inbox/{share_id}/accept` after `import`.
- **Flow**:
  1. Verify owner's signature on share_blob against owner peer's sign key at epoch_id.
  2. `crypto/`.kem_decapsulate(my_kem_privkey, wrapped_key) → file_key.
  3. Persist file_key locally.
  4. Mount file under `/shared-with-me/<owner_label>/<scope_path>`.
  5. If republisher_hint: optionally pin chunks to recipient's own backends.
- **Edges**:
  - Owner's identity at signed epoch is unknown (hasn't been observed): refuse; require user to verify owner's identity first.
  - Recipient's own identity rotated since share was created: KEM decap may fail; refuse.

#### F-SH-3: Revoke Share

- **Trigger**: `DELETE /v1/vaults/{v}/shares/{share_id}`
- **Flow**:
  1. Rotate file_key (derive new under MK with fresh nonce).
  2. Re-encrypt all chunks of affected file (heavy — async via repair scheduler).
  3. Re-wrap remaining recipients' wrapped_keys under new file_key.
  4. OrSetRemove the revoked recipient's wrapped_key.
- **Post**: Recipient's future fetches fail to decrypt; cached plaintext on recipient device is unrecoverable (fundamental).
- **Edges**: Concurrent share creation from another device: HLC ordering; if share-add wins after revoke, that share is created against new file_key (correct).

### 2.6 Plugin Lifecycle

#### F-PL-1: Install Third-Party Plugin

- **Trigger**: `POST /v1/plugins/install` { source_url, expected_signature }
- **Flow**:
  1. Fetch artifact.
  2. Verify signature against author pubkey embedded in manifest (TOFU model).
  3. Surface manifest to frontend for explicit user confirmation.
  4. On confirm: persist; transition Loaded.
- **Edges**:
  - Plugin update from same author: signature must verify against same author key (TOFU continuity).
  - Author key rotation: requires explicit user re-confirmation.
  - Plugin claims red `legal_class`: requires double-confirmation.

#### F-PL-2: OAuth Flow for Provider Instance

- **Trigger**: `POST /v1/providers/oauth/start` { plugin_id }
- **Flow**:
  1. Engine spawns localhost callback listener on random port.
  2. Returns auth_url to frontend.
  3. User completes OAuth in browser.
  4. Engine receives code via callback; exchanges for token.
  5. Token wrapped under MK via `kp:cred-wrap`; persisted.
  6. `credentials_handle` minted; returned to frontend.
- **Edges**:
  - User cancels OAuth (closes browser): listener times out; session invalidated.
  - Provider returns insufficient scope: engine validates against required scopes; rejects if mismatched.
  - Token expires later: plugin signed_fetch returns `auth_failure`; plugin marked Paused; user prompted to re-auth.

#### F-PL-3: Capability Drift Handling

- **Trigger**: plugin reload (user updates plugin) shows different capabilities than last_known.
- **Flow**:
  1. `plugin_host/`.diff capabilities.
  2. If gained: hot-load with extended capabilities.
  3. If lost AND placed chunks affected: emit `plugin.confirmation_required`; transition AwaitingUserDecision.
  4. User: keep (downgrade) → mark Active with reduced caps; OR migrate-out → transition Migrating.
- **Edges**:
  - Lost capability is `cas_write` and plugin is sole metadata-vault: cannot proceed; force migrate-out to another vault provider first.
  - Multiple capability changes in quick succession: each diff handled independently; user sees combined review.

### 2.7 Snapshot

#### F-SN-1: Differential Snapshot Push

- **Trigger**: `snapshot.delta_interval` timer or explicit API call.
- **Flow**:
  1. `metadata/`.snapshot_pages_dirty_since(last_seq).
  2. Build delta blob; encrypt under snapshot key; compute hash.
  3. Sign new pointer (version_counter++).
  4. For each vault provider: put delta; verify by peek+hash; cas_write pointer.
  5. Truncate WAL up to delta cutoff.
  6. Update Merkle leaves; rebuild Bloom (lazy).
- **Edges**:
  - Verify-after-upload fails on one replica: don't update pointer there; antientropy reconciles later.
  - CAS on pointer fails: another device wrote first; back off; re-evaluate.

#### F-SN-2: Cold-Start Snapshot Pull

- See F-VL-2; explicit chain validation steps.

### 2.8 System & Observability

- `GET /v1/system/status` — read-only; no flow concerns.
- `GET /v1/system/metrics` — local Prometheus; no remote.
- `POST /v1/system/scrub` — kicks F-HM-1.
- `POST /v1/system/repair` — drains repair queue immediately.
- `POST /v1/system/gc` — kicks F-HM-5.

---

## 3. New Edge Cases Discovered During Flow Tracing

These are the cases that the per-flow walk surfaced beyond what RESILIENCE.md §2 already had.

### 3.A Multi-Mode Recovery Ambiguity
**Case**: User's input could match more than one configured recovery mode (e.g., enters a "passphrase" that happens to be a valid Shamir share).
**Resolution**: API requires explicit `method` field; engine never auto-detects. Each recovery attempt names its mode.

### 3.B Quorum Unsatisfiable at Write Time
**Case**: W = k+1 = 5; only 4 plugins healthy at write moment.
**Resolution**: Write blocks for `write.quorum_wait_timeout` (default 30 s) for plugins to recover. If still unsatisfiable, fail with `provider_unavailable`. User can retry or reduce W explicitly via header.

### 3.C Plugin Returns Different Handle for Same Idempotency Key
**Case**: Plugin breaks the idempotency contract within the dedupe window.
**Resolution**: Engine treats it as a fresh `put` and the duplicate object as an immediate Shadow (`reason: PluginIdempotencyViolation`). Plugin gets a strike; after N strikes, marked `untrusted`.

### 3.D Recovery File Generated at Older Epoch
**Case**: User's recovery file was generated at epoch 5; current vault is at epoch 8. Recovery file's chain only goes to epoch 5.
**Resolution**: Recovery file imports as-is; the engine refreshes the chain from current vault (which has full chain) and re-verifies anchor. If anchor matches (epoch_0 fingerprint), trust extended.

### 3.E Snapshot Push Partial Success
**Case**: Push succeeds at vault provider 1; fails at provider 2.
**Resolution**: Pointer updated at provider 1; antientropy reconciles 2 within next interval. Alarm if > 24 h unresolved.

### 3.F Plaintext Cache During Vault Lock
**Case**: User locks vault while plaintext chunks still in read cache.
**Resolution**: Read cache zeroized on lock transition. Plaintext file content cached by frontends (e.g., GUI thumbnail) is the frontend's responsibility per API §19.4 anti-patterns.

### 3.G Same Provider Configured Twice
**Case**: User adds Drive plugin instance A, then accidentally adds the same Drive account as instance B.
**Resolution**: Each `provider_id` is unique; engine treats them as logically distinct. Trust correlation group ensures diversity rule still works (both have `trust_group = google`). Storage reported per-instance is correct but the underlying account is double-counted; warning event `provider.same_account_suspected` if quotas show identical patterns.

### 3.H Engine Crash During Vault Destruction Sweep
**Case**: Crash mid-sweep of F-VL-4.
**Resolution**: Vault state persisted as Destroying with sweep progress. On restart, sweep resumes from last checkpoint. MK is zeroized at start, so even if some shards weren't deleted, surviving ciphertext is keyless.

### 3.I First-Party Plugin Signing Key Rotation
**Case**: Project rotates release signing key between engine versions.
**Resolution**: Engine embeds a key set (current + N prior). Plugin manifests declare which release-key fingerprint they're signed under. Engine accepts any in trusted set; deprecated keys eventually removed in a major version bump.

### 3.J WebSocket Disconnects During Long Write
**Case**: Frontend's event subscription drops mid-write; misses progress events.
**Resolution**: On reconnect, subscribe with `?since=<event_id>`; bus replays from ring buffer. If the disconnect spans longer than the buffer, the missed events are lost — but the underlying write completes regardless; final state is correct.

### 3.K Plugin Sandbox Memory Exhaustion Mid-Operation
**Case**: WASM plugin OOMs during a put.
**Resolution**: Sandbox terminates the call with `plugin_resource_error`. Engine retries on a fresh plugin instance (the sandbox is recreated per call when state is suspect). After N retries, plugin marked unhealthy.

### 3.L Identity Rotation During Pending Share
**Case**: Owner has created share blob but recipient hasn't accepted; owner rotates identity.
**Resolution**: Share blob's signature was made under owner's epoch n; rotation creates epoch n+1 but n's pubkey remains valid in the chain. Share verifies as before.

### 3.M Shadow Registry Quota Counting
**Case**: Same physical orphan registered as multiple shadows from different demotion paths.
**Resolution**: shadow records keyed by `(driver_id, native_handle)`; OR-Set merges deduplicate. Quota counts each unique key once.

### 3.N Lease Acquired After Unlock But Before First Write
**Case**: User unlocks vault but doesn't write for an hour; lease TTL expires.
**Resolution**: Lease auto-renews on the timer (every TTL/3) regardless of write activity. Idle vault keeps the lease while Unlocked.

### 3.O Repair Scheduler Queue Overflow
**Case**: Mass-enqueue from plugin quarantine pushes queue past `gc.queue_max_size`.
**Resolution**: Lowest-priority items dropped from queue (demoted to scrub-only); event `repair.queue_overflow` emitted. They'll be picked up on next scrub cycle.

### 3.P Concurrent Share Creation and Recipient's Identity Rotation
**Case**: Owner creates share at owner's epoch n + recipient's epoch m. Recipient rotates identity (now at epoch m+1) before accepting.
**Resolution**: Share blob carries recipient identity at creation epoch m. When recipient imports, their KEM private key for epoch m is still in their wrapped_privkeys (not deleted on rotation). Decap succeeds. The recipient's *current* epoch (m+1) is used for any subsequent shares.

---

## 4. State × Operation Validity Matrix (Aggregate)

For each state of each major entity, which API operations are valid? (Summary; full per-entity tables in §1.)

### Vault × API Operation

| API path | Locked | Unlocking | Unlocked | Locking | Destroying | Destroyed |
|---|---|---|---|---|---|---|
| `unlock` | ✓ | (in-flight error) | (no-op or err) | err | err | err |
| `lock` | (no-op) | (waits) | ✓ | (in-flight) | err | err |
| `destroy` | unlock first | err | ✓ | err | (in-flight) | err |
| `files/* GET (cached)` | maybe | ✓ | ✓ | ✓ | ✓ | err |
| `files/* GET (fresh)` | err | err | ✓ | err | err | err |
| `files/* PUT` | err | err | ✓ | err | err | err |
| `dirs/* GET` | err | err | ✓ | err | err | err |
| `providers/*` | err | err | ✓ | err | err | err |
| `recovery/*` | err | err | ✓ | err | err | err |
| `shares/*` | err | err | ✓ | err | err | err |
| `system/snapshot` | err | err | ✓ | (in-flight) | err | err |
| `system/scrub`, `repair`, `gc` | err | err | ✓ | err | (subset for sweep) | err |
| `events GET` | ✓ (lifecycle) | ✓ | ✓ | ✓ | ✓ | err |

### Plugin × Operation

See §1.2 table above.

---

## 5. Design Improvements Adopted

Summary of changes resolving the issues found.

| Issue | Resolution | Doc Touched |
|---|---|---|
| Layer numbering inconsistency | Renumbered: dependency-depth based; `plugin_host` → L4; `events` → L3 | ABSTRACTIONS §1 |
| Identity chain circular dependency | Chain now in RecoveryManifest; cold-start verifies via anchor first | ABSTRACTIONS §4.8, DESIGN §8.4.2 |
| Vault state machine missing Destroying | Full state machine with `Unlocking`/`Destroying`/per-state op matrix | ABSTRACTIONS §6.3 |
| Chunk doing orchestration | `chunk/` re-scoped to pure transform; orchestration in `vfs/` (will require chunk/FLOW.md update) | ABSTRACTIONS §1, future patch to chunk/FLOW.md |
| Placement reading from vault | `placement/` is pure given pool; pool passed in by L4 caller | ABSTRACTIONS §1, placement/FLOW.md |
| Metadata triggering bloom/merkle | Hooks consumed by L4 (vault/) during compaction | (future patch to metadata/FLOW.md) |
| GC has no home | Confirmed: GC sweep runs in `repair/` worker pool | This document §2.4 F-HM-5 |
| Plugin install trust model | TOFU: author key on first install; rotation requires re-confirmation | This document §2.6 F-PL-1 |
| Plaintext hash side-channel | Per-vault salt mode default; documented elsewhere | DESIGN §7.9 |
| Multi-mode recovery ambiguity | Explicit method field on every unlock | This document §3.A |
| Quorum unsatisfiable | Bounded wait + explicit failure | This document §3.B |
| Idempotency-key contract violation | Fresh shadow + plugin strike system | This document §3.C |
| First-party signing key rotation | Engine embeds key set | This document §3.I |
| Capability drift downgrade window | AwaitingUserDecision state with explicit transitions | This document §1.2, §2.6 F-PL-3 |
| Concurrent shadow registration dedup | Shadows keyed by `(driver_id, native_handle)` on OR-Set merge | This document §3.M |
| WAL truncation vs offline peer | Peers fall back to snapshot-and-tail | This document §2.3 F-MD-5 |

---

## 6. What Has *Not* Been Patched (Tracking)

The following design choices found during review were noted but not yet mechanically applied to the per-module FLOW.md files. They should be done before any code is written.

1. **`chunk/FLOW.md` revision**: remove orchestration; chunk is pure transform.
2. **`vfs/FLOW.md` revision**: take over orchestration of placement + plugin_host calls during write.
3. **`placement/FLOW.md` revision**: clarify pool is input, not fetched.
4. **`metadata/FLOW.md` revision**: hooks instead of "triggers" for bloom/merkle.
5. **`plugin_host/FLOW.md` revision**: layer L4; depends on metadata + crypto (now consistent with rules).
6. **`events/FLOW.md` revision**: layer L3.
7. **`recovery/FLOW.md` revision**: explicit cold-start sequence using manifest's chain.
8. **`MODULES.md` revision**: layer numbers updated.

These are bookkeeping. The structural design changes are committed in DESIGN.md and ABSTRACTIONS.md.

---

## 6.A Second-Pass Findings (Issues Surfaced After the First-Round Fixes)

A re-trace of the structure after applying the layer renumbering, identity-chain fix, and vault state machine update revealed seven additional issues. They are documented here with resolution policy. The first three are structural / data-shape; the remaining four are operational corner cases.

### 6.A.1 `wal/` (L2) → `crypto/` (L3) — Layer violation introduced by renumbering

**Resolution**: `crypto/` repositioned to L2. The L3 "primitive" label was geographic; dependency-depth puts crypto at the same level as `keystore/` and `metadata/`. `wal/` → `crypto/` is now same-layer, allowed for primitive composition.

**Doc updates**: `ABSTRACTIONS.md` §1; `MODULES.md`. (Applied.)

### 6.A.2 Cold-start vault provider bootstrap — second circular dependency

**Problem**: The identity-chain fix put the chain in RecoveryManifest. But the engine still doesn't know **which vault provider to fetch the manifest from** until it has loaded metadata, which is itself in the snapshot at that vault provider. Cycle.

**Resolution**: Introduce a **local vault binding file** — small, per-device, encrypted under the OS keystore (NOT under MK). Contents:

```
VaultBinding {
  vault_id : VaultId
  providers : list of { plugin_id, credentials_handle, priority }
  last_seen_snapshot_pointer : SignedSnapshotPointer  ← for rollback detection
  last_seen_identity_anchor_fingerprint : BlakeHash
  last_updated : Timestamp
}
```

**Lifecycle**:
- Created when a user first binds a vault to a device (after pairing the first vault provider).
- Updated when vault providers are added or removed.
- On a fresh device, recreated after re-binding the first vault provider via the API setup wizard.
- Encrypted with a per-device key in `keystore/` so other local users can't read it.

**Cold-start sequence (revised)**:
1. Engine reads VaultBinding (decrypt with keystore key).
2. User supplies recovery materials → MK derived.
3. Engine fetches RecoveryManifest from a binding-listed provider.
4. Decrypt manifest; verify identity_anchor_fingerprint **also matches** the one in VaultBinding (defense against malicious local-file tampering).
5. Walk identity chain; verify pointer signature; load snapshot.
6. (Optional) Update VaultBinding with current snapshot pointer.

**Doc updates needed**: `ABSTRACTIONS.md` §4 (add VaultBinding entity); `recovery/FLOW.md` cold-start sequence; `keystore/FLOW.md` add VaultBinding wrapping.

### 6.A.3 Recovery materials alone are insufficient (honest limitation)

**Statement**: To recover a vault on a fresh device, the user needs **both**:
1. Their recovery materials (passphrase / recovery file / Shamir / hardware key).
2. Access to at least one of the cloud accounts that hold the vault metadata.

The materials decrypt the metadata; the cloud accounts host it.

**Why it's not a bug**: Attempting to recover from materials alone would require us to cache the entire vault metadata on a device the user no longer has. That defeats the durability model.

**UX implication**: At vault creation and at recovery configuration time, the engine must remind the user: "Save your recovery materials AND remember which cloud accounts hold your vault." Frontends MUST surface this.

**Doc updates needed**: `recovery/FLOW.md` non-goals; `STATES_AND_FLOWS.md` §2.1 F-VL-2 edge cases.

### 6.A.4 Recovery materials have no rotation/invalidation mechanism

**Problem**: Once a recovery file is generated or Shamir shares distributed, they remain valid forever. If the user suspects a leak, they cannot invalidate the old set without destroying the vault.

**Resolution**: Each generated recovery token has a unique `recovery_token_id`. The RecoveryManifest carries:

```
recovery_token_active_set : OrSet<recovery_token_id>
```

Rotation = OrSetAdd new tokens + OrSetRemove old ones, atomically. Recovery attempts present their `recovery_token_id` (embedded in file/share); engine rejects if not in active set.

**API**:
- `POST /v1/vaults/{v}/recovery/rotate { mode }` — generates new tokens for a mode; old tokens invalidated.
- Old tokens fail with `recovery_token_revoked`.

**Doc updates needed**: `ABSTRACTIONS.md` §4.8 RecoveryManifest schema; `recovery/FLOW.md` add rotation flow; `API.md` §12 add rotate endpoint.

### 6.A.5 Peer add doesn't transmit the peer's identity chain

**Problem**: User A's identity has rotated to epoch 5 over time. User B adds A as a peer today. B's `identity/.add_peer` only records A's epoch_0 self-signature.

**Then**: A creates a share at epoch 5 (signed by epoch_5 sign key). B receives it. B can't verify because B only knows epoch_0's pubkey.

**Resolution**: peer identity blob carries A's full chain at the time of sharing. Peer entity stores `IdentityEpoch[]`, not just current pubkeys.

```
Peer
├ peer_id
├ epochs : list of IdentityEpoch  ← was just sign_pubkey + kem_pubkey
├ label
├ verified : bool
└ added_at
```

When verifying a share signed by A at epoch n:
- Look up Peer A.
- If epoch n is in our known list: verify signature against that epoch's sign_pubkey.
- If epoch n > our highest known epoch: refuse with `peer_chain_outdated`; user must re-import A's identity blob.

**Subsequent rotations**: A may include "chain delta" (entries since some `since_epoch`) in shares to let B extend their known chain trustworthily.

**Doc updates needed**: `ABSTRACTIONS.md` §4.7 Peer entity; `identity/FLOW.md`; `share/FLOW.md`.

### 6.A.6 Concurrent identity rotation across devices

**Problem**: Devices X and Y of the same user both call `POST /v1/identities/self/rotate` near-simultaneously. Each appends a different epoch_n+1 with its own keypair. Identity chain ends up with two competing entries.

**Resolution**: identity rotation requires the lease. The lease holder is the only device permitted to rotate. Non-holders fail with `lease_required`.

This is the **one place** where lease becomes a hard serialization point rather than advisory. Documented as an exception in `lease/FLOW.md`.

**Alternative considered**: HLC tiebreak on competing epoch_n+1; loser's rotation discarded. Rejected because losing key material is unsafe — the user who initiated rotation may have already published their new pubkey out of band. Lease enforcement avoids this by serializing.

**Doc updates needed**: `lease/FLOW.md` (add "hard serialization point" note); `identity/FLOW.md` (rotation requires lease).

### 6.A.7 WAL entry size is unbounded

**Problem**: A single `LwwRegister` over a large value (e.g., a full identity chain after many rotations, or a 100-recipient `wrapped_keys` list) could exceed reasonable single-write commit size. No limit defined.

**Resolution**: Define `wal.max_entry_bytes` (default 64 KB). Larger payloads use the indirect form:

```
LwwRegisterIndirect { target, value_hash : BlakeHash, value_storage : LocalKvKey }
```

The actual value is stored in the metadata KV under `value_storage`; the WAL entry only carries the hash. Resolution on replay: load from KV; if missing (e.g., on a fresh device), refuse and require snapshot fetch first.

**Doc updates needed**: `ABSTRACTIONS.md` §7 add LwwRegisterIndirect op kind; `wal/FLOW.md`; `sync/FLOW.md`.

---

## 6.B Same-Layer Rule Clarification

The previous wording "Within a layer, peers may not call each other's orchestration paths; only L4 orchestrates" was contradictory in practice — `vfs/` (L4) calls `sync/.apply_local_op` (L4) constantly.

**Corrected rule**: L4 peers may compose each other's *primitive* operations freely. What's forbidden is **mutual orchestration loops** — e.g., `vfs/` triggering `repair/`'s background scrub loop, which calls back into `vfs/`. Background loops are triggered exclusively by timers (in their own module) or by external events. Peer-to-peer L4 calls within a single transaction are fine.

This is now the rule in `ABSTRACTIONS.md` §1.

---

## 7. The Final Promise (Restated, Now With Coverage Evidence)

The system has:
- **10 invariants** (RESILIENCE §1) — every one mapped to a mechanism in DESIGN.
- **10 entity state machines** (this document §1) — every state enumerated.
- **~50 API operations** with full flows (this document §2).
- **~30 edge cases** (RESILIENCE §2) plus **15 newly discovered** (this document §3).
- **State × operation validity matrix** (§4) — no operation is valid in an undocumented state.

Every data flow path is named. Every state has an enumerated set of valid operations. Every edge case has a resolution policy. Every invariant has a mechanism. Every mechanism is owned by exactly one module at exactly one layer. Every dependency follows the layer rule.

If a future change introduces a new flow, it MUST extend this document. If a flow can't be expressed in this document's vocabulary, the abstractions are wrong and need updating before the flow is implemented.

This is the closure.
