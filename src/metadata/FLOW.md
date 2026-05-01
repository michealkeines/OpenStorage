# metadata/ — Metadata Store (LSM KV; the master)

**Layer**: L2.
**Role**: implements `MetadataStoreContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.14). The on-disk authoritative state of everything. Every entity ultimately lives here.

## What lives here

- Embedded LSM KV (RocksDB or sled, decision pending). Sized for ~10 GB.
- Logical column families: `files`, `chunks`, `shards`, `shadows`, `peers`, `shares`, `devices`, `vault_meta`, `bloom_state`, `merkle_state`, `wal_index`.
- Transactional writes (atomic across multiple keys per CRDT op application).
- Snapshot page enumeration: `snapshot_pages_dirty_since(seq)`.
- Format-version field on every record envelope; migrations live here.
- Trained-dictionary zstd compression for cold pages.

## Boundaries

- Depends on `types/`, `entities/`.
- Receives writes from `wal/` replay (canonical path) and from L4 services (via wal/ first).
- Read by every L4 service.
- The only module allowed to actually persist entity bytes.

## Flow — Write

```
   L4 service has produced a CRDT op
                          │
                          ▼
                 wal/.append(op)
                          │
                          ▼
                  sync/.apply(op)
                  (CRDT merge logic)
                          │
                          ▼
       metadata/.begin_txn()
       metadata/.put(key, value) × N
       metadata/.commit_txn()
                          │
                          ▼
       LSM in-memory memtable → SST flush → compaction
```

## Flow — Read

```
   L4 service needs entity X
                          │
                          ▼
         metadata/.get(key) → Option<bytes>
                          │
                          ▼
       deserialize via entities/ ; return to caller
       (L4 may cache hot records in its own memo)
```

## Flow — Snapshot

```
   vault/ requests differential snapshot
                          │
                          ▼
         metadata/.snapshot_pages_dirty_since(last_seq)
                          │
                          ▼
         stream of SnapshotPage records (opaque envelopes)
                          │
                          ▼
         vault/ encrypts + uploads to vault providers
                          │
                          ▼
         metadata/.mark_snapshot_committed(seq)
         wal/.truncate(seq)
```

## Inputs

- Op-applied writes from `sync/`.
- Read queries from L4 services.
- Snapshot enumeration requests from `vault/`.

## Outputs

- Persisted bytes.
- Snapshot page streams.
- Read responses.

## Invariants this module preserves

- **I7 (deterministic cold start)** — every persisted record carries `format_version`; migrations are forward-only and online.
- **I5 (no silent leaks)** — `shadows` column family is first-class; never collapses.
- **I9 (honest accounting)** — capacity planner queries here for pool-aware totals.

## Implementation notes

- LSM is preferred over B-tree for the WAL-heavy workload pattern.
- Transactions span all keys touched by a single CRDT op application. `OrSetAdd` on the namespace tree may touch parent and child rows together.
- Page format: opaque CBOR envelopes (per [`DESIGN.md`](../../DESIGN.md) §5.3). The store doesn't introspect payload bytes; only the page index, version, and codec tag matter.
- Compaction emits a `pages_changed` notification (event on the `events/` bus); `vault/` (L4) subscribes during snapshot rotation and orchestrates Bloom-filter + Merkle-leaf rebuilds. metadata/ does not call into bloom/merkle directly (would be L2 → L3, upward).
- Migrations: the only module that knows how to rewrite a v1 page into v2. Other modules only see the current version.
- Hot-path reads use a per-thread memo / arc-cache layer to avoid serde overhead on repeated lookups.

## Tests

- Round-trip put/get.
- Crash-safety: kill process mid-commit → no partial-commit visible after restart.
- Snapshot enumeration is monotonic per `(page_id, page_version)`.
- Migration: a v1-format vault opens, transparently rewrites to v2 on first dirty-page write, never produces a hybrid mid-state visible to readers.
- Compression: zstd dictionary saves ≥ 30% on metadata pages at scale.
