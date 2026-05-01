# entities/ — Record Types with Identity

**Layer**: L1 (foundation; depends only on `types/` at the same layer).
**Role**: defines every persistent entity: Vault, VaultBinding, File, Chunk, Shard, Shadow, Provider, VaultProvider, Identity (with epoch chain), Peer, Device, Share, RecoveryManifest, LeaseRecord, SignedSnapshotPointer, WalEntry, SnapshotPage.

## What lives here

The records described in [`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §4. For each entity:

- Field list with types (drawn from `types/`).
- Which fields are CRDT-managed (`LWW_SET`, `LWW_REGISTER`, `OR_SET`, `Counter`) vs. immutable.
- Serialization shape (CBOR envelope with `format_version`).
- Validation rules (e.g., `inline_payload XOR chunk_list`; `epoch_id` strictly increasing in identity chain).

## Boundaries

- Depends on `types/` only.
- Contains no logic beyond construction, serialization, and validation. Mutations go through the relevant L4 service, never directly.

## Flow

No flow of its own. Other modules construct, serialize, validate, and persist these entities.

```
                ┌─────────────────────────────────────┐
                │ entities/                           │
                │   • Vault, File, Chunk, Shard,      │
                │   • Shadow, Provider, ...           │
                │   • Validation rules                │
                │   • CBOR (de)serialization          │
                └─────────────────┬───────────────────┘
                                  │
       ┌──────────────┬───────────┼───────────┬──────────────┐
       ▼              ▼           ▼           ▼              ▼
   metadata/    sync/ apply   vfs/ ops    plugin_host/   vault/ snapshot
                                          ser/de
```

## Invariants this module supports

- **I7 (deterministic cold start)** — every entity has a versioned serialization that older clients refuse to write but newer clients can migrate.
- **I5 (no silent leaks)** — `Shadow` is a first-class entity with required `cached_elsewhere_risk` and `counts_against_quota` fields, so it can't be reduced to a debug log entry.
- **I6 (eventual consistency)** — fields are explicitly tagged as CRDT-managed or immutable, so multi-device merge knows what semantics each field has.

## Implementation notes

- Validation runs at construction *and* at deserialization. A malformed record from disk should fail loudly.
- `format_version` on every record; migrations live in `metadata/` (the only module that knows how versions evolve).
- Every entity has a `to_cbor` / `from_cbor` pair plus a `merge(other)` for CRDT-managed fields.
- The shard list inside `Chunk` is ordered by `shard_index` (not by storage location). Reconstruction needs the order.
- `WalEntry.signature` covers everything *except* the signature itself (canonical CBOR).

## Tests

- Round-trip serialization for every entity.
- Validation rejects: `inline_payload` and `chunk_list` both set; `epoch_id` not monotonically increasing; signature over wrong canonical form.
- Property test: `merge` is commutative, associative, idempotent for every CRDT-managed field.
