# types/ — Identifiers & Value Types

**Layer**: L1 (foundation; no dependencies).
**Role**: defines every identifier and value type used in the system. No logic, no I/O — just shapes.

## What lives here

- All identifier types from [`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §2 (`VaultId`, `FileId`, `ChunkHash`, `ShardId`, `ShadowId`, `DeviceId`, `PeerId`, `IdentityId`, `ShareId`, `ProviderId`, `PluginId`, `EpochId`, `WalEntryId`, `IdempotencyKey`, `CredentialsHandle`).
- All value types from §3 (time/causality, cryptographic, capacity/health, trust/legal, plugin interaction, errors).

## Boundaries

- This module **must not** depend on any other module in the engine.
- This module is a leaf: every other module imports from it.
- No I/O, no time, no randomness; pure shapes plus equality, ordering, and serialization.

## Flow

This module has no flow of its own. It is referenced everywhere else.

```
┌────────────────────────────────────────────────┐
│ types/                                         │
│   • Identifier types (opaque to higher layers) │
│   • Value types (Hlc, AeadNonce, ECScheme, …)  │
│   • Error code enum                            │
└──────────────────────┬─────────────────────────┘
                       │ used by everything
                       ▼
                  every other module
```

## Invariants this module supports

- **I5 (no silent leaks)** — by giving `ShadowId` a stable identity from day one.
- **I7 (deterministic cold start)** — by defining serialization shapes for every persisted type.
- **Cross-cutting opaque-identifier rule (§10.5)** — identifiers are opaque to layers above their generator.

## Implementation notes

- Identifiers MUST be order-preserving for any field that may be used as a key in the metadata KV (e.g., `WalEntryId` ordering follows `(device_id, seq)`).
- `Hlc` requires a custom comparator: order by `(physical, logical)`; tiebreak by `device_id` for deterministic merge.
- `ChunkHash` must NOT be derived from raw plaintext if the vault uses `vault_salted` mode — see [`../chunk/FLOW.md`](../chunk/FLOW.md).
- Every type that crosses the persistence boundary needs a stable serialization (CBOR with field tags). Format-version field on every record envelope.
- No `String` for identifiers that will be compared frequently — interned newtypes for lookup speed where it matters.

## Tests

- Round-trip serialization for every type.
- Ordering relations preserved across serializations.
- HLC `compare` and `merge` properties:
  - Reflexive, transitive, total order.
  - `merge(a, b) ≥ both inputs` (monotonicity).
