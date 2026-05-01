# vfs/ — Virtual Filesystem Service

**Layer**: L4.
**Role**: implements `VfsContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.11). Translates path-level operations (open, read, write, stat, list, rename, unlink) into chunk + metadata operations. **Owns the orchestration of writes and reads** — calls `chunk/` for pure transforms, `placement/` for shard provider selection, `plugin_host/` for actual put/get, `wal/` and `metadata/` for persistence. Hosts the hedged-read scheduler.

## What lives here

- Path → file_id resolution (uses namespace tree in `metadata/`).
- File handle management (open file → cursor + lock state).
- **Orchestration of write path**: chunk/.split → chunk/.encrypt + ec_encode → vault/.current_pool → placement/.pick_shards → plugin_host/.invoke put × N in parallel → wait W=k+1 acks → wal/.append → metadata/.commit.
- **Orchestration of read path with hedging**: lookup chunks → vault/.current_pool → placement/.pick_K+H_replicas → plugin_host/.invoke get × (K+H) in parallel → first K to complete cancels rest → chunk/.ec_reconstruct → chunk/.decrypt → stream to caller. On verify fail: enqueue to repair/.
- Directory listing with cursor pagination.
- Rename via `PATH_MOVE` op.
- Unlink (decrement chunk refcounts; refcount=0 enqueues to `repair/`-shared GC sweep).
- Permission and lock semantics.

## Boundaries

- Depends on `types/`, `entities/`.
- Calls `chunk/` for split/encrypt/reassemble.
- Calls `placement/` indirectly (via chunk/).
- Calls `wal/` for every mutation; reads `metadata/` for resolution.
- Called by `api/` (handlers under `/v1/vaults/{v}/files`, `/dirs`).

## Flow — Write a File

```
   API → vfs/.open(path, write_mode)
                          │
   vfs/ resolves path:    │
     - if exists: ├ get current file_id, check write conflict via etag
     - if new:    └ allocate FileId; create File entity (LWW_REGISTERs; chunk_list empty)
                          │
                          ▼
   API streams body bytes ──► vfs/ ──► chunk/.split(stream)
                                              │
   for each emitted chunk:    chunk/ encrypts, EC-encodes
                              chunk/ asks placement/ for shard providers
                              chunk/ asks plugin_host/ to put shards
                              quorum acks → chunk record done
                                              │
                                              ▼
   vfs/.commit:
     - WAL append OrSetAdd on file.chunk_list (per chunk hash)
     - WAL append CounterInc on chunk.refcount
     - WAL append LwwRegister on file.size, mtime, content_type
     - metadata/.commit_txn
                          │
                          ▼
   API ← vfs/.close(handle) — etag = derived from chunk hashes
```

## Flow — Read a File

```
   API → vfs/.open(path, read_mode)
                          │
   vfs/ resolves: get File entity (chunk_list or inline_payload)
                          │
        ┌─────────────────┴───────────────────┐
        │ inline_payload: decrypt, return     │
        │ chunk_list: stream chunks via chunk/.read_chunk
        └─────────────────────────────────────┘
                          │
                          ▼
   chunk/ does hedged reads + reassembly + AEAD decrypt
                          │
                          ▼
   API streams plaintext to client
```

## Flow — Rename

```
   API → vfs/.rename(src, dst)
                          │
   vfs/ verifies src exists, dst doesn't (or overwrite policy)
                          │
                          ▼
   wal/.append PathMove {
     from_path: src, to_path: dst, file_id,
     linked_remove_id, linked_add_id }
                          │
                          ▼
   metadata/ commit; namespace tree reflects new layout
                          │
                          ▼
   ⟶ event file.changed
```

## Flow — Unlink

```
   API → vfs/.unlink(path)
                          │
   vfs/ resolves to FileId
                          │
                          ▼
   wal/.append LwwRegister on file.exists = false
   for each chunk in file.chunk_list:
     wal/.append CounterInc(chunk.refcount, -1)
   metadata/ commit
                          │
                          ▼
   GC sweep (running in repair/'s worker pool) eventually
   sees refcount=0 chunks and tries delete on each shard's plugin
```

## Inputs / Outputs

- Inputs: path-level operations from `api/`; streams of bytes.
- Outputs: streams of bytes, file metadata, directory listings.
- Side: emits `file.write.progress`, `file.changed`, `file.inline_promoted`.

## Invariants this module preserves

- **I1, I2** — never sees ciphertext directly; relies on `chunk/` for crypto. But it *does* see plaintext within the engine's trusted boundary.
- **I5** — every mutation goes through `wal/`; no out-of-band direct writes to `metadata/`.
- **I6** — every mutation is a CRDT op; multi-device merge handles the rest.

## Implementation notes

- Path strings are UTF-8 normalized at entry. The namespace tree uses normalized form throughout.
- Permissions are POSIX-shaped but advisory at this layer; access control beyond owner is via shares.
- `If-Match` semantics on the API map to optimistic-concurrency by etag (etag = last `LwwRegister` HLC of file.size + chunk_list root hash).
- Tiny-file cutoff: `chunk/.split` returns either a single inline blob OR a chunk stream; vfs/ stores accordingly. A subsequent write that grows past threshold must convert inline → chunked atomically (single transaction).
- Range writes (`PATCH`) re-encrypt only affected chunks. A range write that crosses chunk boundaries re-encrypts each crossed chunk fully; no partial-chunk encryption.

## Tests

- Read-after-write consistency on the same handle.
- Concurrent writes to different paths: independent.
- Concurrent writes to the same path: optimistic-concurrency (etag mismatch) returns 412.
- Inline ↔ chunked transitions both ways.
- Rename then read returns the same content.
- Unlink decrements refcount; GC eventually removes shards.
