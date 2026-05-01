# wal/ — Write-Ahead Log + Hybrid Logical Clock

**Layer**: L2.
**Role**: append-only log of CRDT operations. Owns HLC generation. Owns the entry-size policy. Every metadata mutation in the system passes through here.

## What lives here

- CRDT op vocabulary (`LwwSet` with `previous_value`, `LwwRegister`, `LwwRegisterIndirect`, `OrSetAdd`, `OrSetRemove`, `CounterInc`, `MapPut`, `MapDel`, `PathMove`).
- HLC generator: `(physical, logical)` pair; clamps physical, increments logical on collision.
- Append: signed-by-device WAL entries, monotonically sequenced per device.
- Read: scan since `(device_id, seq)` for replay.
- Truncate: drop entries up to a snapshot cutoff.
- Entry-size policy enforcement: reject entries larger than `wal.max_entry_bytes` (default 64 KB); callers must use `LwwRegisterIndirect` for oversized values **except for security-critical fields** which forbid indirection (see indirect-eligibility policy below).
- Indirect-eligibility check: `LwwRegisterIndirect` ops targeting forbidden fields (`File.wrapped_keys`, `Vault.identity_chain`, `Vault.allowed_devices`, `RecoveryManifest.*`, `Vault.snapshot_pointer`, `LeaseRecord.*`) are rejected with `indirection_forbidden`. The forbidden-targets list is hardcoded; adding new entries requires a format-version bump.

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (for signing — both at L2; same-layer composition is fine for primitives).
- Persists to `metadata/` at the byte level; logically separate from the metadata KV.
- Read by `sync/` for merge; by `vault/` for snapshot replication.

## Flow

```
   any L4 service calls wal/.append(op):
     1. wrap op in WalEntry envelope
     2. assign HLC:
          phys = max(now_ms, last_seen_remote_physical)
          if phys == last_phys: logical += 1; else logical = 0
     3. sign with device key
     4. atomically append to local WAL file
     5. notify subscribers (sync/, vault/) of new tail
   
   sync/ on remote merge:
     for each incoming WalEntry:
       verify signature against allowed_devices in Vault
       update HLC: max(local, incoming) → next generated phys
       hand op to sync/.apply_remote_op for CRDT merge
   
   vault/ on snapshot rotation:
     wal/.truncate(up_to_seq) — drop entries fully captured by snapshot
```

## Inputs / Outputs

- Inputs: CRDT ops from L4 services; remote WAL entries from `vault/` pulls.
- Outputs: persisted entries; new-tail notifications.
- Side: HLC drift correction (a far-future incoming entry bumps the local HLC physical).

## Invariants this module preserves

- **I5 (no silent leaks)** — `LwwSet` carries `previous_value`; the merge path can detect concurrent-update demotion.
- **I6 (eventual consistency)** — HLC + canonical op encoding gives total order across devices.
- **I7 (deterministic recovery)** — replaying the WAL on a fresh device produces identical state.

## Implementation notes

- Append must be crash-safe: `fsync` before notifying.
- Each entry is signed by the originating device's per-device sign key (derived under `kp:device`).
- Rejection of unsigned/forged entries happens at the `sync/` boundary, not here. `wal/` doesn't gate; it only stores.
- HLC physical is milliseconds since epoch in u64; logical is u32. Wraparound far in the future; not a real concern.
- Keep the WAL file independent of the metadata KV; truncation is "drop the oldest segments."
- A WAL entry's canonical encoding (for signatures) is CBOR with deterministic field ordering.
- Entry-size policy: on `append`, measure the canonical-encoded size. If > `wal.max_entry_bytes`, return `entry_too_large`. The caller (`sync/`) is responsible for rewriting oversized payloads into `LwwRegisterIndirect` form before appending — see [`../sync/FLOW.md`](../sync/FLOW.md).
- The indirect-value blobs themselves live in `metadata/` under a separate column family; they replicate alongside snapshot pages and are fetched on demand during WAL replay if missing locally.

## Tests

- Append/scan round-trip.
- HLC monotonicity: any sequence of appends, the HLCs are strictly increasing in op order.
- HLC drift: an incoming entry with phys 5 minutes ahead → local HLC adjusts; subsequent appends maintain ordering.
- Crash-safety: kill process mid-append → on restart, partial entry is discarded; valid entries up to the last fsync are intact.
- Signature: an entry with a bad signature is *stored* (not gated here) but the merge path rejects it.
