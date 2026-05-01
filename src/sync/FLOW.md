# sync/ — CRDT Merge Engine

**Layer**: L4.
**Role**: implements `SyncContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.6). Applies local CRDT ops, merges remote ops, owns the rules for every op kind. **The single most important correctness module.**

## What lives here

- `apply_local_op(op)`: validate, persist via `wal/`, apply to `metadata/`.
- `apply_remote_wal_segment(stream)`: verify signatures, apply each remote op via the merge rules.
- Op-kind merge semantics:
  - `LwwSet`, `LwwRegister`: HLC-ordered last-writer-wins. `LwwSet` includes the **previous-value demotion rule** (the Case-6 fix from RESILIENCE §2.B.3).
  - `LwwRegisterIndirect`: same HLC ordering as `LwwRegister`. The actual value lives in `metadata/` under `value_storage_key`. On apply: ensure the blob is resolvable; if missing, mark target as `unresolved_indirect` and request blob via vault/anti-entropy. Reads of an unresolved indirect target block until resolved.
  - `OrSetAdd` / `OrSetRemove`: observed-remove set semantics; remove cancels only adds it has observed.
  - `CounterInc`: commutative integer counter.
  - `MapPut` / `MapDel`: per-key OR-Set semantics.
  - `PathMove`: linked OR-Set ops with conflict-history retention.
- **Oversized-op rewriting**: before calling `wal/.append`, sync/ checks the encoded size. If > `wal.max_entry_bytes`, sync/ writes the value to `metadata/`'s indirect-blob column family (keyed by `BLAKE3(value)`), then constructs an `LwwRegisterIndirect` op carrying only the hash + storage key. Caller of `apply_local_op` is unaware of the rewrite.
- HLC management (delegates to `wal/`).

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (signature verify), `wal/`, `metadata/`.
- Called by `vfs/`, `repair/`, `share/`, `recovery/`, `vault/`, etc. — every module that mutates state.
- Pulled by `vault/` from peer-device WAL segments.

## Flow — Apply Local Op

```
   any L4 service: "I want to mutate state"
                          │
                          ▼
   sync/.apply_local_op(op):
     1. validate op shape
     2. wrap in WalEntry with current device's HLC + signature
     3. wal/.append(entry)
     4. apply merge rule against current metadata/ value
     5. metadata/.commit_txn
                          │
                          ▼
   ⟶ event (depending on op: file.changed, share.created, etc.)
```

## Flow — Apply Remote WAL Segment

```
   vault/.fetch_wal_segments(peer, since_seq)
                          │
                          ▼
   for each WalEntry in incoming stream:
     look up entry.device_id in Vault.allowed_devices → DeviceAuthorization
     if not found: reject (unknown device)
     verify entry.signature against DeviceAuthorization.device_pubkey
     ── HLC-windowed authorization check (CR-2 fix) ──
     reject if entry.hlc < authorized_from_hlc
     reject if revoked_at_hlc is Some AND entry.hlc >= revoked_at_hlc
     accept otherwise
                          │
                          ▼
     advance local HLC: max(local, entry.hlc)
                          │
                          ▼
     dispatch by op_kind (the heart of the module):
       LwwSet / LwwRegister:
         compare HLC; later wins (tiebreak by device_id)
         if LwwSet AND remote.previous_value ≠ local current:
           ── DEMOTION: emit OrSetAdd(shadows, {handle: local current,
                                                reason: ConcurrentUpdateDemoted})
       OrSetAdd:
         insert (add_id, value) into target's OR-Set
       OrSetRemove:
         only cancel adds whose add_id is in remove_for_add_ids
       CounterInc:
         atomic add to target's counter
       MapPut / MapDel:
         per-key OR-Set; same semantics scoped per map_key
       PathMove:
         apply linked remove + add atomically; if HLC-tied path also moved
         here, retain loser in concurrent_rename_history
                          │
                          ▼
   metadata/.commit_txn (one txn per remote segment)
```

## Inputs / Outputs

- Inputs: local ops from any L4 service; remote WAL streams from `vault/`.
- Outputs: persisted state via `metadata/`; events.
- Side: emits demotion ops (which become new local WAL entries) when concurrent-update conflicts are detected.

## Invariants this module preserves (the core's heart)

- **I5 (no silent leaks)** — the demotion rule on `LwwSet` is what prevents orphan ciphertext from concurrent multi-device updates.
- **I6 (eventual consistency)** — every op kind is commutative + associative + idempotent; replaying the same WAL on any device produces the same state.
- **I7 (deterministic recovery)** — replaying the WAL from a snapshot reproduces the snapshot's successor states.

## Implementation notes

- The demotion op (when triggered) is itself a `OrSetAdd(shadows, …)`. It enters the WAL like any other op and propagates to other devices — so all devices converge on the same shadow set.
- Signature verification is hard-required. An entry with an invalid signature is dropped and logged; never applied.
- HLC must be monotonic per device. A clock-jump backward triggers HLC clamp (use `max(local_phys, last_phys) + 1` in logical).
- Path moves: implement OR-tree CRDT semantics. Concurrent renames produce a `concurrent_rename_history` log per parent dir; user can review via API.
- The op-kind switch is the entire correctness surface. Property-based tests (commutativity, idempotency, associativity) on every op kind are mandatory.

## Tests

- For every op kind: `apply(apply(s, op_a), op_b) == apply(apply(s, op_b), op_a)` (commutativity).
- For every op kind: applying twice = applying once (idempotency).
- LWW with `previous_value` mismatch: demotion op emitted.
- OrSet remove with unobserved add_id: no effect.
- PathMove concurrent: both ends consistent; loser retained in history.
- WAL forks of 1000 ops on each side, then merge: both devices converge to identical state.
- Adversarial: revoked-device WAL entries are rejected.
