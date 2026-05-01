# placement/ — CRUSH-Style Placement Engine (Pure)

**Layer**: L3.
**Role**: implements `PlacementContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.4). Decides which `ProviderId` each shard of each chunk lives on, and answers "where would this go now?" queries for the rebalancer.

> **Pure with pool as input.** placement/ does NOT read provider state from any other module. The caller (`vfs/` for writes, `repair/` for repairs) supplies a `PoolSnapshot` (obtained via `vault/.current_pool()`) as a parameter. Given the same pool and the same chunk identifier, placement returns the same answer — deterministic, idempotent, no I/O.

## What lives here

- Deterministic pseudo-random placement: `H(chunk_hash || shard_index, weighted_pool) → ProviderId`.
- Capacity-weighted CRUSH-style algorithm.
- Trust-correlation-group diversity enforcement.
- Dynamic EC selection: chooses `(k, n)` based on healthy distinct trust groups.
- Tier-aware routing (hot → fast, cold → cheap).
- Per-provider stats: rolling p95 latency, success rate, quota remaining.
- Untrusted-quota tracking: detects divergence between plugin's reported quota and observed write success.

## Boundaries

- Depends on `types/`, `entities/`.
- Does NOT call into `metadata/`, `vault/`, `plugin_host/`, or any other module. The L4 caller passes the `PoolSnapshot` as input.
- Pure computation given a pool. Same input → same output across runs.

## Flow — Pick Shards for a New Chunk

```
                Chunk write request
                 (chunk_hash, target tier)
                          │
                          ▼
       ┌──────────────────────────────────┐
       │ available_groups = distinct trust│
       │   groups in healthy plugin pool  │
       │ N_chosen = min(groups, N_max)    │
       │ if N_chosen < K_target+1:        │
       │   replication mode               │
       │ else: EC(K_target, N_chosen)     │
       └────────────────┬─────────────────┘
                        │
                        ▼
       ┌────────────────────────────────────────┐
       │ for each shard_index in 0..N:          │
       │   weights[p] = remaining_quota(p)      │
       │              × health_score(p)         │
       │              × tier_match(p, tier)     │
       │              × user_weight(p)          │
       │   pick = consistent_hash(              │
       │     chunk_hash || shard_index, weights)│
       │   if pick.trust_group already used     │
       │     by prior shards of this chunk:     │
       │     advance to next-best by hash order │
       └────────────────┬───────────────────────┘
                        │
                        ▼
              list of (shard_index, ProviderId)
```

## Flow — Repair / Rebalance Target

```
        chunk_hash → list of current (shard_index, ProviderId)
                          │
                          ▼
        recompute optimal placement under current pool
                          │
                          ▼
        diff: which shards now live on suboptimal providers?
                          │
                          ▼
        list of (shard_index, new_target_ProviderId)
        (handed to repair/ or rebalancer for execution)
```

## Inputs

- Plugin pool snapshot (every active provider with capabilities, health, quota, latency, trust group).
- Chunk hash and target tier.
- EC scheme parameters (or `auto` to derive).

## Outputs

- Pure: list of (shard_index, ProviderId) pairs.
- Per-provider stats updates (after each observed result, fed back via the API).

## Invariants this module preserves

- **I3 (availability)** — diversity rule guarantees no single trust group holds all shards of a chunk.
- **I9 (honest accounting)** — over-quota providers get zero weight; untrusted-quota providers are derated.
- Determinism: same chunk + same pool → same placement (consistent hashing property; topology change re-places only ~1/N of chunks).

## Implementation notes

- Use a vetted consistent-hashing library or implement straw-style weighted hashing (per Ceph CRUSH paper).
- Trust-correlation graph is data, not code — declared per plugin manifest. Two plugins in the same group correlate; different groups don't.
- Replication mode is just `(k=1, n=R)`. Same algorithm.
- Rolling p95 latency: per-provider sliding-window histogram, decayed exponentially. Fed by observations from `chunk/` reads.
- Untrusted-quota detection: if a put returned `quota_exceeded` while plugin reports >5% free three times in a row, plugin enters `untrusted_quota` state; effective capacity uses a probed estimate (small test put).
- Tier match: cold tier prefers `durability_class >= yearly`; hot tier prefers low p95 latency.

## Tests

- Determinism: same input → same output across runs.
- Stability: removing one provider re-places ~`1/|pool|` of chunks, not all of them.
- Diversity: across many chunks, no chunk has two shards in the same trust group.
- Capacity: a 4 TB plugin draws ~200× more shards than a 20 GB plugin (proportional weights).
- Dynamic EC: pool of 3 trust groups → replication mode; pool of 7 → EC(4,7); pool of 13 → EC(4,13) capped at N_max.
- Untrusted-quota: simulate a dishonest plugin → effective capacity downgraded after 3 quota_exceeded observations.
