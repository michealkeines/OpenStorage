# Future Improvements

Forward-looking work items discovered during architecture review. Each item names the problem, the workload that triggers it, and a proposed direction. Not yet a commitment to build — a tracked backlog of known limitations in the current design.

## Resolved During Review

- **Filesystem semantics under CRDT (was: tree-CRDT problem).** Resolved internally by the path-as-`LWW_REGISTER` model + read-time namespace projection. API surface and all §6 flows unchanged. See DESIGN.md §5.8 ("Namespace Projection & Merge") and §6.13 ("Namespace Projection at Read Time"). Concurrent renames converge by HLC; same-path collisions render via deterministic conflict-copy paths; deleted directories with surviving children resurrect via implicit-directory rule. No frontend changes required.

---

## 1. Metadata Budget — Workload Sensitivity

### 1.1 Current State

`DESIGN.md` §1.4 advertises:

| Metric | Realistic | Headroom |
|---|---|---|
| Per-vault metadata | ~10 GB | up to 15 GB |
| Per-vault user data | ~1 TB | ~5 TB |
| Chunks per vault | ~50 M | bounded by budget |

These three numbers are **internally inconsistent** under the 4 MB fixed-chunk default (Decision #9):

- 1 TB ÷ 4 MB = ~256 K chunks (not 50 M)
- 50 M chunks × 4 MB = 200 TB of user data (not 1 TB)
- 50 M chunks ↔ 1 TB only if average chunk size is ~20 KB (CDC-style, not the default)

### 1.2 Per-Chunk Cost (as currently specified)

| Record | Size |
|---|---|
| CHUNK record | ~180 B |
| 7 SHARD records | ~940 B |
| FILE record share | ~150–280 B |
| **Per chunk total** | **~1.3–1.4 KB** |

Implication: 15 GB ÷ 1.4 KB ≈ **~10 M referenced chunks** is the hard ceiling.

### 1.3 Workload Bands for 1 TB

| Avg file size | Chunk count | Metadata cost | Fits in 15 GB? |
|---|---|---|---|
| ≤ 4 KB (inline) | 256 M files | ~1 TB (payload lives in FILE record) | **Catastrophic — no** |
| 5 KB – 50 KB | 20–200 M chunks | 28–280 GB | **No** |
| 50 KB – 100 KB | 10–20 M chunks | 14–28 GB | **Borderline / no** |
| 100 KB – 1 MB | 1–10 M chunks | 1.4–14 GB | Yes |
| 1 MB – 4 MB | 256 K – 1 M chunks | 0.4–1.4 GB | Yes (trivially) |
| ≥ 4 MB | ≤ 256 K chunks | < 1 GB | Yes (trivially, ~15× headroom) |

**The cliff is ~100 KB average file size.** Below it, 15 GB is not enough for 1 TB.

### 1.4 The Root Cause

Metadata cost is **per-chunk**, but chunk size is **fixed at 4 MB**. For files smaller than 4 MB, each file becomes one sub-4-MB chunk, so chunk count tracks file count, not byte count. The 7× EC fan-out turns this into ~1.4 KB metadata per small file regardless of payload — a 2.8 % overhead at 50 KB files, ~28 % at 5 KB.

### 1.5 Time-Varying Growth Axes (Unbounded in Spec)

Even on a workload that fits today, these drift the footprint upward indefinitely:

1. **Shadow shards** — persist until vault destruction; no compaction.
2. **Snapshot generation retention** — no explicit cap.
3. **WAL transient** during initial bulk load — ~500 MB before first snapshot.
4. **Identity epoch chain** — appended on every rotation, never compacted.
5. **`wrapped_keys[]`** — grows linearly with recipients × shares.

These are slow growers; they don't break 15 GB for any reasonable user lifetime under normal use, but they have no ceiling.

---

## 2. Proposed Improvements (Highest Leverage First)

### 2.1 Pack Small Files Into Shared Chunks

**Problem solved**: small/tiny-file workloads exceed 15 GB at 1 TB.

**Idea**: files below a packing threshold (e.g., 256 KB) are batched into shared 4 MB chunks. The shared chunk is stored once with one set of 7 shard records. The FILE records reference the chunk hash plus an `(offset, length)` slice.

**Effect**: chunk count becomes proportional to *bytes*, not *file count*. A 4 MB packed chunk holds ~80 of the 50 KB files; their shared shard records amortize across all of them. Per-file metadata cost drops by 50–100×.

**Trade-offs**:
- Updates to a packed file rewrite the whole packed chunk (and create shadow on backends that don't `removed`).
- Sharing a single small file requires sharing the packed chunk's key — needs slice-scoped key wrap or per-slice keys.
- Existing CDC-attack defense (Decision #30) already names "packing" as a sub-mechanism for CDC mode. This proposal generalises packing as a small-file strategy regardless of CDC.

**Status**: not in current design. Highest-leverage single change for budget honesty.

### 2.2 Right-Size The Bloom Filter

**Problem solved**: 60 MB Bloom is fixed for 50 M chunks even when the actual vault holds 256 K. ~99 % wasted.

**Idea**: size Bloom dynamically to current chunk count (e.g., resize at every snapshot when load factor crosses thresholds). Or drop it entirely once chunk size is large enough that dedup gains are negligible.

**Effect**: ~60 MB → ~300 KB at 256 K chunks. Cheap win.

**Status**: not in current design. Trivial to add.

### 2.3 Bound Shadow Growth With Compaction

**Problem solved**: shadows are unbounded across vault lifetime.

**Idea**: after T days (configurable, default ~30), demote individual shadow records into a per-driver aggregate — `{driver_id, count, total_bytes, oldest_added_at}`. Aggregate suffices for honest accounting and vault-destruction reporting. Per-shadow detail is dropped.

**Trade-off**: loses the ability to attempt per-shadow recovery later if a backend changes its mind about deletion. Acceptable — by the time T elapses, that's already not actionable.

**Status**: not in current design.

### 2.4 Cap Snapshot Generation Retention

**Problem solved**: indefinite snapshot retention bloats the local cache.

**Idea**: keep last N generations explicitly (default N = 2: current + previous, for rollback safety). Older generations garbage-collected.

**Status**: implied by "snapshot rotation" in §6.6 but not specified. Spec the cap.

### 2.5 Move Volatile Fields Out Of Durable Metadata

**Problem solved**: fields like `access_count_window`, `health_score`, `p95_read_latency_ms`, `last_verified_at` (per-shard) inflate every CHUNK/SHARD record and don't need cross-device consistency.

**Idea**: split records into **durable** (truth) and **operational** (hint) sections. Operational section is local-only, rebuildable on unlock, never in the snapshot, never in WAL. Coarsen `last_verified_at` to a "scrub cohort" — one timestamp per weekly bucket of shards, not per shard.

**Effect**: ~30–50 B per shard record reclaimed → tens of MB at scale.

**Status**: not in current design.

### 2.6 Derive What Can Be Derived

**Problem solved**: per-shard nonces stored when they could be derived.

**Idea**: per-shard nonce = `HKDF(chunk_key, "shard-nonce" ‖ shard_index)`. Don't store. Save 12 B × N shards per chunk (~22 MB at 1.84 M shards).

**Status**: not in current design. Crypto review needed before adoption.

### 2.7 Intern Native Handles Per Driver

**Problem solved**: opaque backend handles (~30–60 B each, e.g., Drive file IDs) repeated across millions of shards.

**Idea**: per-driver dictionary; reference handles by short index (4 B) plus a per-driver structure that holds the full handle once per containing folder/path.

**Effect**: ~30–50 B saved per shard at scale.

**Status**: not in current design.

---

## 3. Decision Order

If only one item is built, build **2.1 (small-file packing)** — it converts 15 GB from a typical-case observation into a real ceiling for arbitrary 1 TB workloads.

After 2.1, **2.3 + 2.4** (shadow compaction + snapshot retention cap) close the unbounded growth axes. Together with 2.1 these three changes make the metadata budget a stable contract rather than a polite suggestion.

The rest (2.2, 2.5, 2.6, 2.7) are tightening passes — each reclaims tens of MB but none structurally change which workloads fit.

---

## 4. Open Questions for Each Improvement

- **2.1**: how does a slice-shared key get rotated when only one of the packed files is shared/revoked? Is per-slice key wrap acceptable overhead?
- **2.3**: does demotion lose any forensic property the threat model relies on? (Vault-destruction residual report uses shadow detail.)
- **2.4**: under multi-device, do all devices need to retain the same N generations, or can each device GC independently?
- **2.5**: are any "operational" fields actually consulted by remote devices during anti-entropy? If yes they're not local-only.
- **2.6**: chunk-key reuse across rotations — does shard-nonce derivation still produce unique nonces under all rotation scenarios?

---

## 5. Out of Scope For This Document

- Performance improvements unrelated to metadata budget (read latency, write throughput, repair scheduling).
- Plugin SDK improvements.
- Frontend UX improvements.
- Cryptographic agility / migration.

These belong in their own future-improvements documents if/when they accumulate enough material.
