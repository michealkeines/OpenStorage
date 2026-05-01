# antientropy/ — Merkle Reconciliation Between Vault Replicas

**Layer**: L4.
**Role**: implements `AntiEntropyContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.8). Periodically compares Merkle roots between configured vault providers; pulls divergent pages; lets `sync/` apply WAL replay to converge.

## What lives here

- Periodic timer (default hourly) that initiates exchange.
- Root-hash exchange with each replica vault provider.
- Subtree walk to localize divergence.
- Page pull for divergent leaves.
- Hand-off to `sync/` for CRDT replay.

## Boundaries

- Depends on `types/`, `entities/`, `merkle/` (tree comparison), `vault/` (page fetches), `sync/` (apply pulled pages).
- Triggered by timer and by `vault/` after suspected drift.

## Flow — Periodic Exchange

```
   timer fires (default 1 h)
                          │
                          ▼
   for each configured VaultProvider replica:
     plugin_host/.invoke(plugin, get, "merkle.root") → remote_root
                          │
                          ▼
     local_root = merkle/.current_root
     if local_root == remote_root:
       continue (no divergence)
                          │
                          ▼
     walk down levels: at each, fetch remote subtree hashes
     identify divergent leaves
                          │
                          ▼
     plugin_host/.invoke(plugin, get, page_id) for each divergent leaf
                          │
                          ▼
     hand pages to sync/ (re-derive ops from page diff,
       OR if pages contain WAL segments, just apply via sync/)
                          │
                          ▼
     ⟶ event anti_entropy.divergence_detected { vault_id, replica, divergent_pages }
                          │
                          ▼
   ⟶ event anti_entropy.run_completed
```

## Flow — Forced Run (manual / on push failure)

```
   API → POST /v1/vaults/{v}/anti-entropy/run
                          │
                          ▼
   skip the timer; same loop runs immediately
```

## Inputs / Outputs

- Inputs: vault provider list; timer; manual API trigger; failed-push signals from `vault/`.
- Outputs: convergence; event emissions; pages fed to `sync/`.

## Invariants this module preserves

- **I6 (eventual consistency)** — independent of CRDT WAL replication path; provides a backstop for any drift between vault replicas.
- **I7 (deterministic recovery)** — a fresh device that picks one vault (the freshest) starts from a state the other vaults will converge with.

## Implementation notes

- Exchange is throttled: `anti_entropy.bandwidth_cap_kbps` default 5000.
- The Merkle tree at each replica is *derived from* the snapshot pages stored there; so this comparison is really "are our snapshot states aligned?"
- For replicas that are simply behind (lower `version_counter`), no pull happens — let normal snapshot push catch them up. Anti-entropy runs only when roots differ but counters are equal.
- If many divergent pages are detected, fall back to a full delta push from the most recent snapshot.

## Tests

- Two replicas synced: roots match, no work.
- One replica missing the latest delta: divergence found at exactly the affected leaves; pulled and applied; convergence achieved.
- Adversarial: replica returning a forged Merkle root → page-level hash check during pull catches the fraud.
- Bandwidth cap respected under load.
