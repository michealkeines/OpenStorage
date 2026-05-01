# repair/ — Priority Repair Scheduler

**Layer**: L4.
**Role**: implements `RepairContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.7). Manages the priority queue of degraded chunks and the workers that repair them.

## What lives here

- Bounded priority heap of chunks awaiting repair.
- Urgency scoring: `(replicas_floor − current_healthy) × W_floor + recency_bonus + access_bonus + hot_data_bonus`.
- Sources of work: scrubber, read-repair detection, plugin health change (mass-enqueue on quarantine), provider quota warning, manual API trigger.
- Repair workers: bounded concurrency; reuse for vault-destruction sweep too.
- Rate-limit budget shared with `gc` (garbage collection sweep).
- Background scrubber: samples 5%/day of chunks, peeks each, enqueues if any shard is missing/corrupt.

## Boundaries

- Depends on `types/`, `entities/`, `metadata/` (queue persistence), `placement/` (target selection), `chunk/` (re-place via `put` with a chosen replica's content), `plugin_host/`.
- Called by `vfs/` (read-repair side effect), `vault/` (plugin quarantine), `recovery/` (destruction sweep reuse), `api/` (manual trigger).

## Flow — Background Scrub

```
   timer (configurable interval)
                          │
                          ▼
   sample 5% of chunks (round-robin across vault)
                          │
                          ▼
   for each sampled chunk:
     for each shard:
       plugin_host/.invoke(plugin, peek, handle)
         → exists / not_found / hash mismatch
       if missing or hash mismatch:
         mark shard Degraded
         enqueue(chunk_hash, source=Scrub, urgency=score)
```

## Flow — Read Repair Enqueue (from `chunk/`)

```
   chunk/.read detects AEAD verify fail on shard S
                          │
                          ▼
   repair/.enqueue(chunk_hash, source=ReadRepair, urgency=HIGH)
   (the read continues from K healthy shards; repair runs background)
```

## Flow — Repair Worker Loop

```
   pop highest-urgency chunk from queue
                          │
                          ▼
   for each Degraded shard in this chunk:
     fetch ciphertext from a Healthy shard (or EC-reconstruct)
     placement/.evaluate_rebalance_targets(chunk_hash) → new target ProviderId
     plugin_host/.invoke(new_plugin, put, ciphertext)
       → new handle
                          │
                          ▼
     wal/.append: LwwSet on shard.driver_id + native_handle (with previous_value)
                  (this triggers concurrent-update demotion if needed via sync/)
                          │
                          ▼
     attempt delete on old plugin (best-effort):
       outcome → register Shadow if Abandoned/Tombstoned/Unknown
                          │
                          ▼
   when chunk's Degraded count returns to 0:
     transition chunk.replication_state → Full
     ⟶ event chunk.replication_state_changed
```

## Flow — Plugin Quarantine Mass Enqueue

```
   provider.health_changed { state: Quarantined }
                          │
                          ▼
   metadata/ scan: list all shards on this ProviderId
                          │
                          ▼
   for each: enqueue(chunk_hash, source=PluginHealth, urgency=HIGH)
```

## Inputs / Outputs

- Inputs: enqueue calls from various sources; periodic timer.
- Outputs: re-placed shards (via `chunk/`), shadow registrations (via `sync/`), events.
- Side: rate-limit budget consumption per plugin.

## Invariants this module preserves

- **I3 (availability)** — degraded chunks return to full redundancy proactively.
- **I4 (no silent loss)** — chunks with `current_healthy < K` get `LwwRegister` on `replication_state = Lost`; emit `chunk.lost`.
- **I5 (no silent leaks)** — repair-replace registers shadows for orphaned old shards.

## Implementation notes

- Queue persists across restarts (state in metadata).
- Workers respect rate-limit budgets per plugin; a plugin in `requires_throttle` mode gets repair work paced.
- Don't repair chunks whose source is `ReadRepair` if they've been re-fetched cleanly since enqueue (check `last_verified_at` after pop).
- Vault-destruction sweep reuses this scheduler with a special "destroy" flag; same rate-limiting applies.
- Bounded queue size: when full, demote oldest items to scrub-only (they'll be picked up on next scrub cycle).

## Tests

- Enqueue + drain: an item with high urgency is processed before a low-urgency one even if older.
- Mass-enqueue from quarantine: every shard on quarantined plugin re-placed within reasonable time.
- Rate-limit interaction: a quarantined plugin that recovers can absorb repair traffic without saturating.
- Persistence: kill engine mid-repair, restart, queue resumes from last persisted state.
- Lost state: simulate failures of (N − K + 1) shards; chunk transitions to Lost, event emitted, event payload lists affected files.
