# OpenStorage — Module Index

> One module per directory; one `FLOW.md` per module describing its data flow, interface contract, dependencies, and invariants. Read [`../ABSTRACTIONS.md`](../ABSTRACTIONS.md) first for the type / interface vocabulary; this file is the table of contents.
>
> **Layer numbering** is by **dependency depth**: a module's layer = `1 + max(layer of its dependencies)`. See [`../ABSTRACTIONS.md`](../ABSTRACTIONS.md) §1 for rationale and rules. The numbering was revised after a flow-tracing audit; some module FLOW.md files still reference the old numbering and will be patched (see [`../STATES_AND_FLOWS.md`](../STATES_AND_FLOWS.md) §6).

## Layered Layout

| Layer | Module | Role |
|---|---|---|
| **L1** — foundation | [`types/`](./types/FLOW.md) | identifiers, value types (incl. RecoveryTokenId, LocalKvKey) |
| **L1** — foundation | [`entities/`](./entities/FLOW.md) | record types incl. VaultBinding, Peer-with-chain |
| **L2** — storage | [`metadata/`](./metadata/FLOW.md) | LSM KV; the master |
| **L2** — storage | [`wal/`](./wal/FLOW.md) | append-only CRDT log + HLC |
| **L2** — storage | [`keystore/`](./keystore/FLOW.md) | OS secure storage adapter |
| **L2** — storage (was L3) | [`crypto/`](./crypto/FLOW.md) | AEAD, KDF, signatures, KEM (primitive byte-ops) |
| **L3** — primitives | [`chunk/`](./chunk/FLOW.md) | pure transform: split, hash, encrypt |
| **L3** — primitives | [`ec/`](./ec/FLOW.md) | Reed–Solomon encode / reconstruct |
| **L3** — primitives | [`placement/`](./placement/FLOW.md) | CRUSH-style shard placement (pure) |
| **L3** — primitives | [`bloom/`](./bloom/FLOW.md) | per-vault Bloom filter |
| **L3** — primitives | [`merkle/`](./merkle/FLOW.md) | Merkle tree for anti-entropy |
| **L3** — primitive (was L5) | [`events/`](./events/FLOW.md) | event bus / pub-sub |
| **L4** — services | [`vfs/`](./vfs/FLOW.md) | VFS; orchestrates writes/reads |
| **L4** — services | [`vault/`](./vault/FLOW.md) | metadata-vault replication |
| **L4** — services | [`lease/`](./lease/FLOW.md) | advisory primary-writer lease |
| **L4** — services | [`sync/`](./sync/FLOW.md) | CRDT op application + merge |
| **L4** — services | [`repair/`](./repair/FLOW.md) | priority repair scheduler + GC sweep |
| **L4** — services | [`antientropy/`](./antientropy/FLOW.md) | Merkle reconcile between vaults |
| **L4** — services | [`recovery/`](./recovery/FLOW.md) | unlock / rotate / destroy lifecycle |
| **L4** — services | [`identity/`](./identity/FLOW.md) | identity epoch chain |
| **L4** — services | [`share/`](./share/FLOW.md) | per-recipient key wraps |
| **L4** — services (was L1) | [`plugin_host/`](./plugin_host/FLOW.md) | WASM runtime + signed_fetch |
| **L5** — interface | [`api/`](./api/FLOW.md) | local HTTP/2 API server |
| **L0** — external | [`../plugins/`](../plugins/) | first-party plugin implementations |
| **L6** — frontends | [`../cli/`](../cli/), [`../gui/`](../gui/), [`../fuse/`](../fuse/) | UX surfaces |

## Dependency Rules

1. A higher-numbered layer may call a lower-numbered layer; the reverse is forbidden.
2. Within the same layer, modules MUST NOT call peers that perform orchestration; only services in L4 orchestrate.
3. L0 (plugins) is reached only through `plugin_host` (L1).
4. L6 frontends speak only via the API (L5); never link the engine directly except for embedded mode.

## Reading Path for a New Contributor

1. `../DESIGN.md` §The Core (5 minutes)
2. `../ABSTRACTIONS.md` §1 (layers) and §5 (interfaces)
3. The FLOW.md for the module you're about to touch
4. The FLOW.md for every module the touched module depends on
