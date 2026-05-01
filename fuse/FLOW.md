# fuse/ — FUSE / WinFsp Filesystem Shim

**Layer**: L6.
**Role**: presents the vault as a POSIX (FUSE) or Windows (WinFsp) filesystem so any local app sees it as a normal mount. Translates filesystem calls into API requests.

## What lives here

- FUSE callback bindings (Linux/macOS via libfuse / macFUSE).
- WinFsp callback bindings (Windows).
- Mount lifecycle: register mount point on start; unregister on stop.
- Aggressive local cache to satisfy POSIX semantics with minimal API round-trips.
- File-handle table: `fh → (vault_id, path, current_etag)`.
- Cache invalidation: subscribes to `file.changed` events to drop stale entries.
- Permission shim: maps POSIX modes to engine permissions, with sensible defaults.

## Boundaries

- Depends only on the API contract.
- Never embeds the engine in-process.
- Caches plaintext locally for read amplification reduction; flushes on close or on `file.changed`.

## Flow — `read(path)` from an OS app

```
   OS app opens file → FUSE callback open(path)
                          │
                          ▼
   API: HEAD /v1/vaults/{v}/files/{path} → etag + size
                          │
                          ▼
   allocate file handle; cache entry initialized
                          │
                          ▼
   OS app: read(fd, off, len)
                          │
                          ▼
   if cached chunk for this range: return it
   else: API: GET /v1/vaults/{v}/files/{path} with Range: bytes=off-len
            stream chunk into local cache; return slice
```

## Flow — `write(path)` from an OS app

```
   OS app opens file → FUSE callback open(path, write)
                          │
                          ▼
   API: HEAD path → etag for If-Match
                          │
                          ▼
   buffered writes accumulate in local staging
                          │
                          ▼
   on close() or sync():
     PUT /v1/vaults/{v}/files/{path}
       If-Match: <etag>
       body: full file (re-stream from cache)
                          │
                          ▼
   on 412 Precondition Failed (someone else modified): surface error to OS
   on 201: update cache + etag
```

## Flow — Cache Invalidation

```
   another device modifies the same file → file.changed event
                          │
                          ▼
   FUSE shim listening on event stream
                          │
                          ▼
   drop cache entries for this path; OS apps re-reading will fetch fresh
```

## Inputs / Outputs

- Inputs: kernel filesystem callbacks; engine events.
- Outputs: response bytes to kernel; API requests.

## Invariants this module preserves

- The shim is a *frontend* — it cannot violate engine invariants. It can only fail loudly (return EIO to the OS) when the engine refuses an operation.
- POSIX semantics best-effort: lock semantics, mtime fidelity, sparse files — implemented as far as the API supports them.

## Implementation notes

- macOS FUSE requires macFUSE / system extension; ship as a separate optional component.
- Windows uses WinFsp; bundle the WinFsp installer with the GUI app.
- iOS/iPadOS does not support FUSE — mobile uses File Provider Extension instead, in a separate frontend module.
- The cache is plaintext and lives in user's home directory; encrypted-at-rest under a per-session key (no persistent caching of plaintext across vault locks).
- Random-access patterns (databases, video editors) cause chunk thrash if naive; implement read-ahead and write-behind based on access pattern detection.

## Test surface

- Mount, ls, cat, write, rename, unlink: all round-trip correctly.
- Concurrent edit from another device: cache invalidates; reread sees new content.
- Large file streaming: doesn't buffer the whole file in memory.
- Integration with common tools (vim, git, rsync) — golden-path testing.
