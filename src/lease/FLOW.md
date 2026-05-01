# lease/ — Advisory Primary-Writer Lease

**Layer**: L4.
**Role**: maintains a TTL-bounded "primary writer" lease record in the metadata vault. Advisory for almost everything; CRDT WAL handles concurrent writes correctly. The lease coordinates snapshot timing, surfaces a "primary device" hint to the user, **and acts as a hard serialization point for one specific operation: identity rotation.**

> **Hard-serialization exception**: see [`../identity/FLOW.md`](../identity/FLOW.md). Concurrent identity rotations would produce competing epoch_n+1 entries with different keypairs — both technically valid, fragmenting trust. Identity rotation (and only identity rotation) requires the lease as a real lock, not advisory.

## What lives here

- Acquire / renew / release lease via `cas_write` on the vault's `lease.json`.
- TTL handling (default 5 minutes; renewed every TTL/3).
- Steal logic: if observed expired by ≥ 2× TTL, another device may take over.
- Signed lease record (Ed25519 over the lease body using `kp:lease-sign`).
- State machine: `Free → Held → Free`.

## Boundaries

- Depends on `types/`, `entities/`, `crypto/` (sign/verify), `vault/` (CAS through vault provider plugins).
- Used by `vault/` (snapshot timing) and surfaced via `api/` to frontends.

## Flow — Acquire on Vault Unlock

```
   recovery/ unlocks vault → emits vault.unlocked
                          │
                          ▼
   lease/.acquire(vault_provider, ttl)
                          │
                          ▼
   vault/.cas_read("lease.json") → current state
   if Free or expired:
     build LeaseRecord, sign it
     vault/.cas_write("lease.json", signed, expected_etag)
       → success → state = Held
       → CAS fail → another device just acquired; back off, retry once
```

## Flow — Renew

```
   timer fires every TTL/3
                          │
                          ▼
   lease/.renew(): refresh expires_at, re-sign,
   vault/.cas_write with current etag
```

## Flow — Release on Lock / Shutdown

```
   vault.locked OR engine shutdown
                          │
                          ▼
   lease/.release(): vault/.cas_write a "Free" record
   (or just let it expire — release is best-effort)
```

## Flow — Steal

```
   another device observes lease.json with expires_at < now - 2×TTL
                          │
                          ▼
   it CAS-writes its own lease record over the stale one
   ⟶ event lease.acquired { vault_id, by_device }
   the previous holder, when it next tries to renew, will fail CAS
   ⟶ event lease.lost { vault_id, to_device }
```

## Inputs / Outputs

- Inputs: vault unlock signal, vault.locked signal, periodic timer.
- Outputs: lease state change events; lease record persisted in vault.
- Side: signed records visible to anyone reading the vault provider.

## Invariants this module preserves

- **I6** — does NOT impede concurrency; CRDT WAL is the real mechanism. Lease is just snapshot-coordination guidance.
- Coordination correctness: CAS gives single-writer atomicity for the lease record itself.

## Implementation notes

- Lease is *advisory* for everything except identity rotation (see top of doc). Even non-holders may write WAL ops; they just shouldn't drive snapshot rotations.
- The lease holder is the device whose dirty pages are most likely to be the source of next snapshot.
- The lease record signature is verified on read; a forged lease record from a malicious vault provider is rejected (would require breaking Ed25519).
- Multiple devices renewing in tight loops can produce CAS contention; each device backs off with jitter on contention.
- Don't fail loudly if vault provider doesn't implement CAS; refuse to use that provider as a metadata vault (declared via `supports_cas` capability).
- Identity-rotation enforcement: `identity/.rotate_identity` calls `lease/.is_holder()`; rejection is `lease_required`, not `precondition_failed`, so frontends can surface "you need to take over the lease from device X" specifically.

## Tests

- Single device: acquire, renew several times, release.
- Two devices: race for acquire; exactly one wins; loser receives `lease.lost` event after stale expiry.
- Forged lease record: signature verification fails; engine treats as Free.
- Vault provider without CAS: refuses to register as metadata vault.
