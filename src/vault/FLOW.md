# vault/ — Vault Manager (metadata replication)

**Layer**: L4.
**Role**: implements `VaultManagerContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.5). Replicates the master metadata snapshot + WAL across the user's chosen vault provider plugins.

## What lives here

- Snapshot push: differential page diffs encrypted under `kp:snapshot`, uploaded as `snapshot.<ts>.delta`.
- Snapshot pointer: signed monotonic counter; atomically swapped via `cas_write` after upload+verify.
- WAL streaming: append-only flush of WAL segments to vault providers.
- Snapshot pull on cold start: fetches latest snapshot, verifies signature against identity chain, hydrates `metadata/`.
- Replica health, divergence summary; coordinates with `antientropy/`.

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (encrypt/sign), `metadata/` (page enumeration), `wal/` (segment scan), `plugin_host/` (vault-role plugins).
- Called by `recovery/` on cold start.
- Triggers `antientropy/` periodically and on detected divergence.

## Flow — Push Snapshot (Differential)

```
   trigger: snapshot.delta_interval timer OR explicit /v1/system/snapshot
                          │
                          ▼
   metadata/.snapshot_pages_dirty_since(last_seq)
                          │
                          ▼
   build delta blob (page records, opaque payloads)
                          │
                          ▼
   crypto/.encrypt(blob, snapshot_key)
   compute hash; sign new snapshot_pointer (monotonic counter++)
                          │
                          ▼
   for each configured VaultProvider (replica priority order):
     plugin_host/.invoke(plugin, put, encrypted_blob)
       → handle
     plugin_host/.invoke(plugin, peek, handle)
       → verify size + hash
     plugin_host/.invoke(plugin, cas_write,
       name="snapshot.current", payload=signed_pointer,
       expected_etag=last_known_etag)
                          │
                          ▼
   wal/.truncate(seq) up to delta cutoff
   ⟶ event snapshot.completed
```

## Flow — Pull Snapshot on Cold Start

```
   recovery/ asks vault/.fetch_snapshot()
                          │
                          ▼
   pick freshest VaultProvider (highest version_counter)
                          │
                          ▼
   plugin_host/.invoke(plugin, get, "snapshot.current") → signed pointer
                          │
                          ▼
   verify pointer's signature against identity chain (identity/)
   reject if version_counter ≤ last_seen_local
                          │
                          ▼
   plugin_host/.invoke(plugin, get, snapshot_id) → encrypted blob
                          │
                          ▼
   crypto/.decrypt → page records
   metadata/.bulk_apply
                          │
                          ▼
   pull WAL segments since snapshot's cutoff (sync/)
   trigger antientropy/ run with other replicas
```

## Flow — WAL Streaming

```
   wal/ emits new-tail notification
                          │
                          ▼
   vault/ batches recent WAL entries
                          │
                          ▼
   for each replica VaultProvider:
     plugin_host/.invoke(plugin, put, wal_segment_blob)
       → handle stored at "wal/<seq>.seg"
                          │
                          ▼
   record last-flushed seq per replica
```

## Flow — Manifest Sync Across Providers (M-4)

The RecoveryManifest lives at a fixed path (`recovery.manifest`) on each vault provider, **outside the snapshot pages**. Because of this, anti-entropy (which reconciles snapshot pages via Merkle trees) does NOT cover the manifest. A separate sync loop is required.

```
   on every manifest update (rotation / chain extension / token rotation):
     vault/.push_manifest_to_all_providers(new manifest):
       for each configured VaultProvider:
         plugin_host/.invoke(plugin, put,
           name="recovery.manifest", payload=encrypted_signed_blob)
       record per-provider success/failure
       on failure: emit provider.health_changed { state: degraded };
                   schedule retry via repair scheduler

   periodic (every manifest_sync_interval, default 1h):
     vault/.reconcile_manifest_versions():
       for each configured VaultProvider:
         plugin_host/.invoke(plugin, get_meta, "recovery.manifest")
           → fetch HEAD-style metadata or small range to read version_counter
       compare version_counters across providers
       if any provider lags:
         pull the highest-version manifest locally
         push it to lagging providers
         emit provider.health_changed { state: caught_up } when complete
```

### Edge cases

- All providers tied at same version: no work.
- Two providers serve different manifests at the same `version_counter` (impossible in normal operation; counter is monotonic and signed): refuse both; emit `manifest.fork_detected`; user must investigate.
- A provider returns `recovery.manifest` with invalid signature or anchor mismatch: treat as tampered; emit `provider.health_changed { state: suspect }`; do not push our manifest there until user confirms.

## Flow — Promote Replica on Primary Failure

```
   primary VaultProvider returns errors persistently
                          │
                          ▼
   demote primary (mark unhealthy)
   pick next replica with freshest snapshot/WAL
                          │
                          ▼
   ⟶ event provider.health_changed { state: degraded }
   continue snapshot/WAL pushes against new primary
```

## Inputs / Outputs

- Inputs: dirty snapshot pages from `metadata/`; new WAL entries from `wal/`; plugin manifest changes.
- Outputs: encrypted blobs to vault provider plugins; pointer swaps; event emissions.
- Side: WAL truncation locally; signature chain verification on cold start.

## Invariants this module preserves

- **I7 (deterministic cold start)** — pointer signature verified; monotonic counter prevents rollback.
- **I3 (availability)** — multi-provider replication; loss of one replica doesn't block.
- **I4** — repeated snapshot verification on push; corrupted upload caught before pointer swap.

## Implementation notes

- Snapshot delta encoding is page-version diff: only pages whose `page_version` advanced get re-uploaded.
- Atomic pointer swap = upload new versioned snapshot, verify, then `cas_write` on the small `snapshot.current` pointer file. If CAS fails (someone else updated), back off and reconcile via antientropy/.
- The signed pointer carries `epoch_id`; cold start verifies the epoch is in the validated identity chain.
- Multi-replica push happens in parallel; success threshold = ≥1 replica acks; rest catch up via antientropy.
- WAL streaming runs continuously; small batches (kilobytes) every `snapshot.wal_flush_interval`.
- Don't wait for full N-replica writes on the hot path; it's eventual consistency by design.

## Tests

- Push then pull on a fresh device: identical metadata state.
- Push then corrupt blob on one replica: pointer swap blocked by verify; antientropy reconciles.
- Replica returning stale pointer: rejected on cold start; freshest counter wins.
- Concurrent pushes from two devices (race): CAS resolves; lease helps but isn't required.
- Adversarial: replica tries to roll back pointer → counter check refuses.
