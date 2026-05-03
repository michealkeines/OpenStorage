# OpenStorage Routing & Placement — Production Design

> **Purpose**: this document is the source of truth for how the engine
> chooses *where to put each chunk*, *where to fetch it from*, *when to
> reroute*, and *how to exploit each backend's quirks*. The thesis: a
> portfolio of N free, limited, anonymous, and partially-broken services
> can dominate any single paid service — but only if routing is *aware
> of every constraint each backend declares*, *adaptive to runtime
> failure*, and *clever about reusing the few capabilities each backend
> does offer* (overwrite, append, edit, range-read, …).
>
> **Read alongside**:
> [`DESIGN.md`](./DESIGN.md), [`RESILIENCE.md`](./RESILIENCE.md),
> [`THREAT_MODEL.md`](./THREAT_MODEL.md),
> [`PLUGIN_SDK.md`](./PLUGIN_SDK.md),
> [`STRUCTURAL_REWORK.md`](./STRUCTURAL_REWORK.md),
> [`STATES_AND_FLOWS.md`](./STATES_AND_FLOWS.md).
>
> **Status**: design proposal. Today's implementation lives in
> [`src/placement/src/lib.rs`](./src/placement/src/lib.rs),
> [`src/plugin_host/src/pool.rs`](./src/plugin_host/src/pool.rs),
> [`src/plugin_host/src/rate_limit.rs`](./src/plugin_host/src/rate_limit.rs),
> and [`src/vfs/src/lib.rs`](./src/vfs/src/lib.rs). See §13 for the
> migration plan.

---

## §0. Problem Statement — the Portfolio Thesis

A single free-tier backend has *some* of these problems:

- per-IP rate limit
- per-object size cap
- no overwrite / no delete / no list
- short retention or single-download TTL
- text-only / image-only content shape
- TLS cert that periodically expires
- terms-of-service that disallow automation
- abrupt operator-shutdown (e.g., 0x0.st in 2026: *"uploads disabled because it's been almost nothing but AI botnet spam"*)
- weak or no idempotency window
- no auth, but no recovery if the engine forgets the handle
- intermittent quota window resets

A *portfolio* of N such backends, **routed properly**, has *none* of these problems if and only if:

1. **Constraints are mostly orthogonal across the pool** — one is rate-limited, another is size-limited, another is delete-unsupported, another is text-only.
2. **Every constraint is a first-class declared property of the plugin**, not implicit.
3. **Placement is a constraint-satisfaction problem**, not a single-scalar weight blend.
4. **Failure modes feed back into placement** within seconds, not human-intervention-later.
5. **Each backend's *positive* capabilities are exploited** — overwrite enables slot reuse, append enables packing, range-read enables streaming, edit enables crypto-erasure on delete-unsupported services.

Today's implementation satisfies (1) and partially (2). It fails on (3), (4), and (5). This document is the design that closes those gaps.

---

## §1. Goals

### 1.1 Hard invariants (must always hold; non-negotiable)

| # | Invariant | Sourced from |
|---|---|---|
| R1 | **Diversity**: distinct shards of one chunk live in distinct trust-correlation groups. | `RESILIENCE.md` I3 |
| R2 | **Capability respect**: a chunk is never assigned to a provider whose declared capabilities cannot serve it (size cap, missing op, banned legal class). | new |
| R3 | **CAS tier respect**: coordination blobs (snapshot pointer, lease, share-grant) only land on `StrongCas` (or quorum-of-three `OptimisticCas`) backends. | `STRUCTURAL_REWORK.md` Layer 3 |
| R4 | **Quorum durability**: writes return success only after W = k + 1 acks, with W providers from W distinct trust groups. | `RESILIENCE.md` I10 |
| R5 | **Honest accounting**: every shadow byte (delete-unsupported orphan) is registered. | `RESILIENCE.md` I5 |
| R6 | **No silent quarantine**: a provider that drops below health threshold is excluded from placement and the user is told. | new |
| R7 | **Crypto invariants unchanged**: routing decisions never expose plaintext; ciphertext is opaque to the router. | `RESILIENCE.md` I1 |

### 1.2 Soft objectives (optimize subject to invariants)

- Minimize **per-shard cost** (bytes-stored × time-stored × abuse-risk × dollar-cost).
- Minimize **tail latency** for hot reads.
- Maximize **storage efficiency** (slot reuse, packing, dedup).
- Minimize **abuse signal** (puts/sec/IP relative to ToS budget).
- Maximize **liveness under partial failure**.
- Maximize **uniformity of wear** across the portfolio (don't burn one provider's quota first).

### 1.3 Non-goals (deliberately not solved here)

- Hiding the *existence* of a vault (out of scope per `THREAT_MODEL.md` §1.3).
- Defending against an adversary holding the master key.
- Optimizing for a single user-supplied paid backend (S3, etc.) — the design works there but the value is in the portfolio case.
- Real-time live migration of in-flight writes (covered by repair, not router).

---

## §2. Plugin-Declared Properties — the Comprehensive Taxonomy

Each plugin declares a `ProviderCapabilityProfile` at registration time and may *update* it via `health()` (capability drift). This profile is the **only** input the router gets about a backend; if a property isn't declared, the router treats it as unknown (which is conservative — unknowns get worst-case routing).

The profile is the union of what's already declared today (`CapabilitySet` in [`src/types/src/plugin.rs:41`](./src/types/src/plugin.rs)) and what this design adds.

### 2.1 Per-operation capability flags (closed set)

Already exist in `Capability` enum:

| Flag | Meaning |
|---|---|
| `Put` | Can store a new blob. (Universal — no plugin without this.) |
| `Get` | Can retrieve a stored blob (full body). |
| `GetRange` (was `RangeRead`) | Can serve `Range:` requests for partial reads. |
| `Peek` | Can answer "does this exist + size + mtime + etag?" without transferring bytes. |
| `Delete` | Can remove a blob and reclaim its bytes. |
| `Tombstone` | `Delete` is at least best-effort; bytes may persist in caches/CDNs. |
| `List` | Can enumerate stored handles (used for cold-start reconciliation). |
| `AtomicReplace` | Can overwrite an existing handle with new bytes; `previous` is gone. |
| `CasWrite` | Compare-and-swap on a *named* (not content-hashed) blob. |
| `SignedFetch` | Can produce a signed, time-bounded read URL. |
| `QuotaReport` | `health()` returns a non-`untrusted` `QuotaState`. |

This design adds the following to the closed set:

| Flag | Meaning | Why |
|---|---|---|
| `Append` | Can extend an existing blob/message with bytes. | Many messaging services (Telegram message-edit, Discord webhook edit, GitHub commit-on-existing-file). Enables append-pack. |
| `Update` | Can rewrite the *contents* of an existing handle while keeping the handle stable. Strict superset of `AtomicReplace`. | `AtomicReplace` may issue a new handle ("replaced via new URL"). `Update` is true in-place: same URL, new bytes. Distinguishing these is critical for slot pooling (§5). |
| `Mutable` | Either `Update` or `AtomicReplace` is supported. Convenience flag. | Most policy questions only care "can I write again." |
| `IdempotentPut` | Same payload → same handle, deterministically, within an idempotency window. | Lets the router safely retry a put without producing a shadow. |
| `MultiPart` | Supports a chunked-upload flow with explicit `init / chunk / finalize`. | Lets the router stream large chunks without buffering. |
| `WebHookDelivery` | Each put is also broadcast to subscribers (Discord, Mastodon). High `cached_elsewhere_risk`. | Confidentiality-preserving but residual-exposure relevant. |
| `ContentSniffing` | Backend inspects/rewrites/re-encodes uploaded bytes (image hosts, video processors). | Forces the use of an opaque-binary wrapper (PNG steganography for image hosts; base64 for text-only services). |
| `RequiresAccount` | Anonymous use is not allowed; engine must rotate accounts. | Account-rotation logic invoked. |
| `LegallyConstrained` | Operator forbids automation in ToS; use carefully (low ops/sec, high jitter). | `AbuseSensor` enforces a smaller per-day budget. |

### 2.2 Quantitative limits (scalar, open-ended)

Already supported as `CapabilitySet.scalar: BTreeMap<String, i64>` ([`src/types/src/plugin.rs:43`](./src/types/src/plugin.rs)). This design canonicalizes the keys:

| Key | Unit | Source |
|---|---|---|
| `max_object_bytes` | bytes | `RateLimitProfile.max_object_bytes` |
| `min_object_bytes` | bytes | new (some hosts reject empty / sub-1KB blobs) |
| `total_quota_bytes` | bytes | `QuotaState.total` |
| `puts_per_sec_steady` | float×1000 | `RateLimitProfile.puts.per_sec` |
| `puts_burst` | count | `RateLimitProfile.puts.burst` |
| `daily_op_budget` | count | new (e.g., Imgur ~30k/day per Client-ID) |
| `concurrent_inflight_max` | count | `RateLimitProfile.max_concurrent` |
| `idempotency_window_seconds` | seconds | new (0 = none) |
| `update_window_seconds` | seconds | new (Discord webhook edit window, Telegram edit window) |
| `account_count` | count | new (how many anonymous accounts the rotator owns for this provider) |
| `bandwidth_per_period_bytes` | bytes | new (Cloudflare R2: 10 GiB egress/month free) |

Unknown keys are tolerated (forward-compat); unknown *required* gates fail closed.

### 2.3 Temporal properties

| Property | Type | Notes |
|---|---|---|
| `retention_class` | enum: `Permanent`, `InactivityTtl(days)`, `FixedTtl(days)`, `SingleDownload`, `Probabilistic`, `Unknown` | Drives chunk-class assignment. |
| `mtime_visibility` | enum: `Strong`, `EventualSeconds(n)` | Some CDNs lag minutes on freshness. |
| `consistency` | enum: `ReadAfterWrite`, `EventualSeconds(n)` | `EventualSeconds` rejects coordination role. |

### 2.4 Trust / operator metadata

Already exist in `Provider` ([`src/entities/src/records.rs:213`](./src/entities/src/records.rs)):

- `trust_correlation_group: TrustCorrelationGroup`
- `legal_class: LegalClass`

This design adds:

| Property | Why |
|---|---|
| `egress_geographic_zone` | Geographic diversity is *real* diversity (CDN region affinity, censorship regimes). Not a blocker but a tie-breaker. |
| `cached_elsewhere_risk: enum { None, Low, Medium, High }` | Already returned by `delete()` per shard; promote to provider-level for the **placement-time** decision (don't put high-confidentiality chunks on Imgur even though it has space). |
| `automation_risk_class: enum { Authorized, Tolerated, Discouraged, Forbidden }` | Encodes ToS reality. Default = `Tolerated` (free public hosts) ≠ `Authorized` (you have an account/contract). |

### 2.5 Operational properties

- `auth_class`: `None` / `ApiKey` / `OAuth(scope)` / `PerRequestSignature` / `RotatedAccount`
- `account_pool_strategy`: `Single` / `RoundRobin(N)` / `LeastUsed(N)` / `JitWithCooldown`
- `cost_class`: `Free` / `Freemium { paid_tier_at_bytes: u64 }` / `MeteredEgress` / `Paid`
- `dollar_cost_per_gb_month`: optional float (for cross-portfolio cost optimization)
- `tls_health`: `Trusted` / `SelfSigned` / `Expired` / `Unknown` (auto-detected; gates routing)
- `dns_health`: `Resolves` / `Flaky(last_failure)` / `Unresolved`

### 2.6 Content-shape properties

| Property | Implication |
|---|---|
| `accepts_arbitrary_binary: bool` | If `false`, the engine wraps shards via a **content-shape adapter** (§10.2). |
| `inferred_mime_required: bool` | Some hosts examine `Content-Type` and reject mismatches. |
| `filename_charset: enum { Ascii, Unicode, Hash }` | Some hosts mangle non-ASCII. |
| `max_filename_length: u32` | Some hosts truncate; we'd then lose a CAS path. |

### 2.7 Idempotency properties

`IdempotentPut` flag + `idempotency_window_seconds` scalar. The router uses these together: if a retry happens *within* the window, the same handle is expected. Outside the window, retries produce shadows by default (and the shadow registry tracks them per `RESILIENCE.md` §2.A.6).

### 2.8 Update / mutability properties (the user's insight)

This is the section the user pushed for. Three orthogonal axes:

1. **Update primitive**:
   - `None` — every put produces a new handle; the old one is permanent until the operator GCs.
   - `AtomicReplace(old_handle) → new_handle` — overwrite "logical" record, but the URL changes. Sees old as a separate handle that must be deleted/shadowed.
   - `Update(handle)` — true in-place: same URL, new bytes. Old bytes are gone after the call returns.
2. **Update window**:
   - `Forever` — git, S3.
   - `Bounded(seconds)` — Discord webhook edit (15 min), Telegram bot edit (48 h).
   - `OnceOnly` — single-shot replace then immutable.
3. **Update granularity**:
   - `Whole` — replace entire content.
   - `Partial(byte_range)` — supports `PATCH` or `Range`-write; rare but exists (S3 multipart; some message-edit APIs).

These three together gate the **slot pool** subsystem in §5.

### 2.9 Append properties

Mostly distinct from Update; covered by the `Append` flag plus:

- `append_window_seconds`
- `append_max_total_bytes` (some services cap total message size after edits)

---

## §3. The Chunk's Request — what placement is told

Today, `pick_shards_for_chunk(chunk_hash, scheme, pool, diversity, tier)` ([`src/placement/src/lib.rs:141`](./src/placement/src/lib.rs)) takes the chunk hash and the EC scheme. That's not enough information to honor R2.

The design adds a `PlacementRequest`:

```rust
pub struct PlacementRequest {
    pub chunk_hash: ChunkHash,
    pub chunk_bytes: u64,                    // for max_object_bytes & quota gate
    pub scheme: ECScheme,
    pub role: ChunkRole,                     // Chunk | SnapshotPointer | Lease | Share | …
    pub access_pattern: AccessPattern,       // ReadMostly | WriteOnce | RewriteFrequent | Hot
    pub redundancy_class: RedundancyClass,   // Standard | Critical | Sacrificial
    pub expected_lifetime: ExpectedLifetime, // Persistent | Bounded(d) | Unknown
    pub mutability_intent: MutabilityIntent, // Immutable | UpdatableSlot | Append
    pub content_shape: ContentShape,         // Opaque | TextOnly | ImageWrapped | …
    pub trust_required: ConfidentialityClass, // Standard | NoCachedElsewhere | Sovereign
    pub deadline: Option<Instant>,           // for tail-latency sensitive ops
    pub previous_assignment: Option<PriorAssignment>, // for repair / rotation
}
```

`ChunkRole`, `RedundancyClass`, and `ExpectedLifetime` are derived by `vfs` from the calling subsystem (vault.rs writes a `SnapshotPointer`, so role=`SnapshotPointer`, lifetime=`Persistent`, etc.). `mutability_intent` lets `vault` say "I will rewrite this chunk repeatedly" (snapshot pointer), unlocking slot routing in §5.

---

## §4. The Routing Pipeline — six stages

Today's placement is a single function. Production routing decomposes into stages, each independently testable. The order matters: hard gates first (cheap to evaluate, fail fast), then soft optimization, then dispatch.

```
PlacementRequest
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 1 — Eligibility filter (hard gates per R2/R3/R6)       │
│ • size fits?  • required caps present?  • cas tier ok?       │
│ • content shape compatible?  • automation_risk acceptable?   │
│ • not currently quarantined / circuit-broken?                │
│ • TLS / DNS healthy?                                         │
└──────────────────────────────────────────────────────────────┘
   │ filtered pool
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 2 — Health filter (recent-failure suppression)         │
│ • SupplierHealthWatcher: last health() result                │
│ • CircuitBreaker per (provider, op): Closed / Open / HalfOpen │
│ • RecentFailureMemory: rolling failure rate over window      │
│ • AbuseSensor: ToS-budget remaining for the day              │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 3 — Slot-pool match (the user's insight)               │
│ • If req.mutability_intent ∈ {UpdatableSlot, Append}:        │
│     try to bind to an existing slot on an Update-capable      │
│     provider before considering fresh-handle allocation.     │
│ • Slots prefer same-trust-group as previous_assignment when   │
│     repair is rotating chunks.                                │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 4 — Cost optimization (multi-objective)                │
│ • compute_weight(req, provider) returns a vector:            │
│   [quota_wear, abuse_wear, dollar_cost, tail_latency,        │
│    retention_fit, geographic_diversity_bonus, …]              │
│ • Pareto-front pruning, then scalarize per current global     │
│   policy (default: cost-min).                                 │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 5 — Diversity enforcement (R1)                         │
│ • Per-shard CRUSH-style consistent hash over the surviving   │
│   pool, with used_groups tracked across shards.              │
│ • If exhausted: PlacementError::InsufficientGroups.          │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 6 — Dispatch (PoolDispatcher with cross-group fallback)│
│ • Each shard gets a candidate list:                          │
│     [primary, same-group siblings, cross-group overflow]     │
│ • Walk by current capacity (estimated_wait); RateLimited /   │
│   Unavailable advances; HardError surfaces per Op semantics. │
│ • On success, record the assignment back into Stage 3's      │
│   slot index if a slot was used.                             │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
PlacementResult { shards: Vec<ShardAssignment>, w_acked, … }
```

### 4.1 Stage 1 details — Eligibility filter

A hard gate is *cheap-to-evaluate* and *correctness-critical*. The order is from cheapest to most expensive so we shed the worst providers first.

```rust
fn eligible(req: &PlacementRequest, p: &PoolEntry) -> Eligibility {
    if p.tls_health.is_broken() { return Reject(TlsBroken); }
    if p.dns_health.is_unresolved() { return Reject(DnsUnresolved); }
    if !p.capabilities.has(Capability::Put) { return Reject(MissingCap("put")); }
    if let Some(cap) = p.scalar.get("max_object_bytes") {
        if req.chunk_bytes > *cap as u64 { return Reject(SizeExceedsCap); }
    }
    if req.chunk_bytes > p.remaining_quota_bytes() { return Reject(QuotaExceeded); }
    if req.role.requires_strong_cas() && !p.cas_tier.is_at_least(StrongCas) {
        return Reject(CasTooWeak);
    }
    if !req.content_shape.compatible_with(&p.content_shape_props) {
        return Reject(ContentShapeMismatch);
    }
    if req.trust_required == NoCachedElsewhere && p.cached_elsewhere_risk > Low {
        return Reject(LeakRisk);
    }
    if req.role.is_coordination() && p.legal_class.is_high_takedown_risk() {
        return Reject(LegalRisk);
    }
    Eligible
}
```

Today none of these checks live anywhere. `placement::pick_shards_for_chunk` doesn't see `chunk_bytes` and `placement::compute_weight` only multiplies four scalars. **Fixing Stage 1 alone would prevent the majority of avoidable write failures observed in §0.**

### 4.2 Stage 2 details — Health filter

Three distinct mechanisms feed Stage 2:

#### 4.2.1 `SupplierHealthWatcher` (new worker)

A periodic supervisor worker (sibling of `Scrubber`, `Gc`, `LeaseRenewer` in the existing supervisor crate) calls `plugin.health()` on every registered provider every `health_interval` (default 60 s; jittered). It writes the result to:

- `Provider.health` (persisted score)
- `Provider.quota` (refreshed)
- `Provider.rate_limit.reset_at`
- `Provider.capabilities` (capability drift)
- `Provider.tls_health` (derived from connection result)

Without this worker, the existing `Provider.health` field is **frozen at registration time**. That's the bug observed in §13.4 below.

#### 4.2.2 `CircuitBreaker` (per provider, per op)

A 3-state machine: `Closed` (all good) → `Open` (no requests; cooldown timer) → `HalfOpen` (probe one request) → back to `Closed` or `Open`.

State transitions:
- N consecutive failures of `op` on `provider` → `Open` for `cooldown(provider, op)`.
- Cooldown elapsed → `HalfOpen`; one probe.
- Probe succeeds → `Closed`; probe fails → reset cooldown, `Open`.

Existing code partially implements this in `HealthMonitor::record_error` ([`src/plugin_host/src/host.rs:53`](./src/plugin_host/src/host.rs)). The design promotes it to a first-class `CircuitBreaker` with explicit per-op cooldowns and probe semantics.

#### 4.2.3 `AbuseSensor` (new)

Per-provider rolling window of "ops in the last 24 h" measured against the provider's declared `automation_risk_class` budget. When the budget is approaching, Stage 2 down-weights (not eliminates — that's `CircuitBreaker`'s job) the provider.

Why separate from `CircuitBreaker`? The signals are different. `CircuitBreaker` reacts to *failures*; `AbuseSensor` reacts to *successful but excessive* traffic that will *cause* failures (a ToS ban) tomorrow.

### 4.3 Stage 3 details — Slot-pool match

See §5 for the full subsystem. Briefly: if the chunk is `UpdatableSlot` or `Append` intent, ask the slot pool "do you have an existing slot on a still-eligible Update-capable provider that I can rebind for this chunk?" If yes, the placement decision becomes "keep the same `(provider_id, slot_id)`, and call `plugin.update(handle, new_bytes)` instead of `put`." If no, fall through to Stage 4 with a hint that the result should be allocated as a new slot.

### 4.4 Stage 4 details — Cost optimization

Today: `compute_weight = quota_factor × health × tier_match × user_weight`. That's a single scalar that conflates very different costs.

Design: a vector of normalized [0..1] cost components, scored together via a configured policy.

```rust
struct CostVector {
    quota_wear: f32,            // bytes / total_quota
    abuse_wear: f32,            // ops_today / daily_budget
    dollar_cost: f32,           // bytes × $/GB-month × normalize
    tail_latency_p99: f32,      // ms / deadline_ms
    retention_fit: f32,         // 1.0 if matches; lower if mismatch
    geographic_diversity: f32,  // 1.0 if new region; lower otherwise
    cached_elsewhere_risk: f32, // multiplier for chunks that are confidentiality-sensitive
}
```

Policy is a weighted L1 norm with operator-tunable weights (the engine's `cfg.placement_policy`). Default policy weights cost-min slightly above latency, and slight bonus for geographic diversity. A "burst write at low latency" policy bumps `tail_latency_p99` weight 10×.

### 4.5 Stage 5 details — Diversity enforcement

This is the existing `pick_shards_for_chunk` loop, *unchanged structurally* but now operating on the (already-filtered + cost-ranked) eligible pool. The CRUSH-style scoring still uses `consistent_hash(chunk_hash, shard_index, provider_id)` so placement remains deterministic.

Critical fix: when fewer than `n` distinct trust groups survive Stage 1 + Stage 2, the design escalates to **degraded placement** (return a partial assignment plus a `degraded` event) rather than today's hard error. The chunk is written with `(k, n_actual)`, marked `Degraded`, and the repair scheduler is asked to fill the missing shards once a fresh trust group becomes available.

### 4.6 Stage 6 details — Dispatch with cross-group fallback

Today's `PoolDispatcher::put_with_fallback` ([`src/plugin_host/src/pool.rs:90`](./src/plugin_host/src/pool.rs)) walks a candidate list given by the caller. The caller (`vfs::persist_chunk`) builds that list as **primary + same-trust-group siblings only**. With ~1 provider per trust group (typical in our portfolio), the list is just `[primary]` — no fallback exists.

Design: the candidate list per shard is

```
[primary,
 same-group siblings (rate-limit liveness, no diversity cost),
 cross-group overflow (diversity-aware: only includes groups not yet
                       used by other shards of this chunk)]
```

Cross-group overflow consults a per-chunk `used_groups` set (the same set Stage 5 maintains) so a fallback never violates R1.

When the dispatch *uses* a cross-group overflow candidate, it emits a `placement.degraded_to_overflow` event. This is observable and tells the operator the canonical placement was unhealthy.

---

## §5. Slot Pooling — the Update-Capable Optimization

### 5.1 Motivation

Several backends in the portfolio support **true overwrite**:

- **GitHub / Codeberg / GitLab** — git push is in-place at a path; same path, new content, same URL.
- **S3 / R2 / B2 / Filebase / Storj** — `PUT` overwrites at the same key.
- **Cloudflare KV / Vercel Blob** — `PUT` overwrites.
- **Telegram bot edit-message** — within 48 h.
- **Discord webhook edit** — within 15 min.

Currently, the engine treats every put as a new handle. Consequences:

- Frequently-rewritten chunks (snapshot pointer rewritten on every commit) generate a fresh handle each time and the previous one is orphaned → shadow registry grows unboundedly.
- For delete-unsupported backends, the orphans are *literal residual ciphertext* the operator will GC at their leisure. We pay storage cost for nothing.
- Repair, when it migrates a chunk for any reason, allocates afresh and forgets to cleanup. Same problem.

The slot pool fixes this.

### 5.2 The slot data model

```rust
struct Slot {
    slot_id: SlotId,                         // engine-assigned, opaque
    provider_id: ProviderId,
    update_capability: UpdateCapability,     // None | AtomicReplace | TrueUpdate
    update_window: UpdateWindow,             // Forever | Bounded(s) | OnceOnly
    update_granularity: UpdateGranularity,   // Whole | Partial { aligned_to: u64 }
    slot_class: SizeClass,                   // power-of-two byte ceiling
    state: SlotState,                        // Empty | Filled | Pending | Dirty | Forgotten
    current_handle: Option<NativeHandle>,    // None when Empty
    current_size: u64,                       // <= slot_class
    owner: Option<ChunkId>,                  // who's renting it
    last_update_at: Timestamp,
    erasure_seed: Option<[u8; 32]>,          // for crypto-erasure on release (§5.5)
    reuse_count: u32,                        // how many writes have hit this slot
}
```

### 5.3 Slot lifecycle state machine

```
       allocate                   bind chunk → write
Empty ──────────► Pending ───────────────────────► Filled
                  │                                  │
                  │ write fails or aborts            │ owner releases
                  ▼                                  ▼
                Empty                            Forgotten
                                                     │
                                                     │ reused by next req
                                                     ▼
                                                  Pending (rebind)

Filled ── update from same owner ───► Filled (current_handle stable if TrueUpdate;
                                              current_handle advances if AtomicReplace,
                                              old handle then handed to ShadowReg)

Filled ── update window expired ────► Frozen (cannot mutate; falls back to
                                               new-allocation path on next write)

Forgotten ── crypto-erase ──────────► Empty (overwrite with deterministic-random
                                              bytes derived from erasure_seed; drop
                                              the seed; bytes-at-rest become
                                              cryptographically inaccessible)
```

### 5.4 The reuse algorithm (Stage 3 placement)

```rust
fn try_bind_slot(req: &PlacementRequest, pool: &Pool) -> Option<ShardAssignment> {
    if req.mutability_intent == Immutable { return None; }
    let class = SizeClass::ceiling(req.chunk_bytes);
    // 1. Same-owner re-bind: chunk is being rewritten; preserve slot identity.
    if let Some(prior) = req.previous_assignment.as_ref() {
        if let Some(slot) = pool.slot(prior.slot_id) {
            if slot.update_window.allows_now() && slot.slot_class >= class {
                return Some(ShardAssignment::Update {
                    provider: slot.provider_id,
                    slot_id: slot.slot_id,
                    handle: slot.current_handle.clone().unwrap(),
                });
            }
        }
    }
    // 2. Rent a Forgotten slot of the right size class.
    if let Some(slot) = pool.find_forgotten_slot(class) {
        return Some(ShardAssignment::Rebind {
            provider: slot.provider_id,
            slot_id: slot.slot_id,
            handle: slot.current_handle.clone().unwrap(),
        });
    }
    None
}
```

Three cases handled:

1. **Same-owner update** — chunk being rewritten (snapshot pointer, frequently-edited file). Stay in the same slot, call `Update`. Old bytes vanish.
2. **Different-owner rebind** — slot was `Forgotten` (its prior chunk was deleted). New chunk takes over the slot, calling `Update`. **No new orphan is created.** This is the win.
3. **No fit** — fall through to Stage 4 and let placement allocate a fresh handle on a fresh-or-existing slot.

### 5.5 Crypto-erasure on delete-unsupported backends

The most powerful trick: a backend that **cannot delete** but **can overwrite** can still satisfy I5 (no silent leaks) by *cryptographic erasure*.

The engine's chunk encryption is per-chunk-key. When a chunk is deleted:

1. Drop the wrapping key from the keystore (already happens — that's how vault destruction works).
2. **Overwrite the slot** with deterministic random bytes (e.g. `BLAKE3(erasure_seed)` keystream) of the same size class.
3. Drop `erasure_seed`.

The ciphertext at rest is now structurally a uniform random blob with no key, no tag, and no structure. It is *cryptographically indistinguishable from /dev/random*. The operator's storage still has bytes, but those bytes are no longer "ciphertext of confidential plaintext" — they are unreadable noise. Confidentiality (I1) and integrity (I2) are preserved without honest delete; the slot becomes safely reusable.

This trick only works for `TrueUpdate` (handle stable across overwrite). `AtomicReplace` (new URL each overwrite) creates a new orphan on every erasure, which defeats the purpose.

### 5.6 Pack-and-unpack (small-chunk coalescing)

Some backends have nontrivial per-object overhead (a Discord webhook message has ~250 B of metadata regardless of attachment size; Telegraph creates a new article URL per upload). For chunks much smaller than the backend's "natural" object size, **pack** N small chunks into one slot and split on read.

- Use only on Update-capable, large-`max_object_bytes` providers.
- Pack until either (a) slot fills, or (b) a packing-window timeout fires.
- The pack header is a CBOR `[(chunk_id, offset, length, …)]` index encrypted with a per-pack key.
- On any chunk's read, the engine downloads the pack once (cached) and slices.
- On any chunk's *delete*, the slot is rewritten without that chunk (`Update` on a `TrueUpdate` provider). On `AtomicReplace` providers, packing is allowed but each pack-rewrite spawns one shadow.

This *inverts* the small-file metadata cliff in [`FUTURE_IMPROVEMENTS.md`](./FUTURE_IMPROVEMENTS.md) §1: instead of every small file taking 1.4 KB of metadata for one shard, packing makes the metadata cost amortize across the whole pack.

### 5.7 When *not* to use the slot pool

- Append-only or content-addressed substrates (IPFS) — every write is a new CID by definition.
- Backends with `update_window < 1 hour` and `mutability_intent != UpdatableSlot` — the window will expire before the next intended write.
- Critical-path coordination blobs — slot-rewrite latency is unbounded; coordination needs StrongCas semantics, not slot semantics.

---

## §6. Adaptive Feedback Loops — the Subsystems

### 6.1 `SupplierHealthWatcher`

Already discussed (§4.2.1). Public API:

```rust
pub struct SupplierHealthWatcher {
    interval: Duration,
    jitter: Duration,
    timeout_per_health_call: Duration,
}

#[async_trait]
impl Worker for SupplierHealthWatcher {
    async fn tick(&self) -> Result<()> {
        for provider in pool.iter() {
            let report = timeout(self.timeout, plugin.health()).await;
            persist(provider.id, report);
            health_monitor.absorb(provider.id, &report);
        }
        Ok(())
    }
}
```

### 6.2 `CircuitBreaker`

Per `(provider_id, Op)`. Implementation of the three-state machine. Exposed metrics: `cb_open_total`, `cb_state_changes`, `cb_probe_outcomes`. Probe-on-half-open uses the cheapest op (`peek` if available, else `health`).

### 6.3 `AbuseSensor`

Rolling window of "successful ops in the last 24 h" per provider. Compared against the provider's declared `daily_op_budget` scaled by `automation_risk_class`. When `usage > 0.8 × budget`, Stage 4 multiplies the provider's cost by 5×; when `usage > 0.95 × budget`, by 50×; when `usage ≥ budget`, the provider is removed from this hour's eligibility.

### 6.4 `CapabilityDriftDetector`

When `health()` returns a `CapabilitySet` different from the persisted one, emit `provider.capability_changed`. *Loss* of a capability triggers manual user confirmation (per `RESILIENCE.md` §2.A.9). *Gain* is hot-loaded.

### 6.5 `IdempotencyTracker`

When the engine retries a put within the declared idempotency window and gets *back* a different handle than before, record the delta and update the provider's actual idempotency window down (drift toward the truth). When the resulting window is below 60 s, log a warning — the provider's idempotency claim is essentially invalid.

### 6.6 `AccountRotator`

For `RequiresAccount` providers (Imgur Client-IDs, Telegram bot tokens, Mastodon OAuth tokens), maintain a *pool of N tokens* per `provider_id`. Rotate strategy per the declared `account_pool_strategy`:

- `RoundRobin(N)` — even spread.
- `LeastUsed(N)` — burn each account uniformly.
- `JitWithCooldown` — keep accounts cool; rotate only when the current is rate-limited.

This converts a single-account `puts_per_sec=1` provider into an effective `N × 1` puts/sec aggregate, at the cost of N tokens.

### 6.7 `QuotaPlanner`

Per pool: predicts when the portfolio's first hard-quota will hit at the current write rate. Emits warning events. Used by Stage 4 to bias new writes toward less-burned providers (uniform wear).

### 6.8 `TtlMigrator`

For chunks placed on `FixedTtl` providers, schedule a re-placement before the TTL expires. The migrator hands a `PlacementRequest` with `previous_assignment` so the slot pool can re-bind to a different provider preemptively rather than reactively.

### 6.9 `LegalClassMonitor`

If a provider's `legal_class` changes (e.g., Imgur revises their AUP to disallow non-image binary content), the monitor triggers a forced **migration** of any chunks placed on that provider that are now non-compliant. This is rare but real (e.g., Imgur cracked down on non-image uploads in 2023).

---

## §7. Failure Modes — Comprehensive Matrix

The exhaustive enumeration of "what can go wrong, how do we detect it, what does the router do, what invariant is preserved." Every row in this table is a thing the design promises to handle.

| # | Failure | Detection | Adaptive response | Invariant preserved |
|---|---|---|---|---|
| F1 | Per-IP rate limit (429 + Retry-After) | wire-level detector | `CircuitBreaker.Open` if frequent; dispatcher reroutes within candidate list; sleep-and-retry on the inflight call only if `< max_rate_limit_wait` | I3, I10 |
| F2 | Daily op budget exhausted (no signal, predicted) | `AbuseSensor` | Stage 4 zeroes the provider's eligibility for the current bucket; restored at window roll-over | R6 |
| F3 | Provider tightens to `RequiresAccount` (e.g., pixeldrain) | first request returns `auth_required` JSON | `CapabilityDriftDetector` updates profile; provider quarantined unless `AccountRotator` has tokens | R6 |
| F4 | Provider quota full (507 or domain-specific 4xx) | wire detector | persist `quota_exhausted=true` with TTL; placement skips | I9, I10 |
| F5 | TLS cert expired | rustls handshake error | `TlsHealthMonitor` flips state; eligibility filter excludes; alert | R6, R7 |
| F6 | DNS unresolvable | resolve error | `DnsHealthMonitor` flips; eligibility excludes; auto-retry health every 60 s | R6 |
| F7 | HTTP 5xx burst (transient) | error rate over 60 s window | `CircuitBreaker.Open` 30 s, exponential cooldown; probes test | I3 |
| F8 | Tampered ciphertext (AEAD tag fail on read) | crypto layer | shard `Degraded`, repair scheduled, provider's `corruption_count++`, threshold-quarantine | I2, R7 |
| F9 | 404 on known-good handle | get fail | shard `Lost`, repair, possibly re-place; if pattern: provider's `loss_count++`, threshold-quarantine | I3, I4 |
| F10 | Provider returns *different* bytes than written (silent corruption) | AEAD tag fail (covered by F8) | same as F8 | I2 |
| F11 | Stale CDN edge (read returns old version) | `If-None-Match` mismatch on `peek` | retry with cache-buster (`?ts=`), warn if persistent | I6 |
| F12 | Handle works for owner but not for fresh client (private auth) | unexpected 401/403 on `get` | classify as auth-bound; mark provider `RequiresAuthForGet`; engine includes credentials on subsequent reads | I3 |
| F13 | Capability silently lost (e.g., delete returns "not_supported" after declaring `Delete`) | drift in `delete()` outcome | `CapabilityDriftDetector` updates profile; engine reroutes deletes | R5, R6 |
| F14 | Idempotency window shorter than declared | retry returns different handle | `IdempotencyTracker` shrinks window; shadow registry takes over | I5 |
| F15 | TTL closer to expiry than declared (premature deletion) | scrub finds chunks gone before declared TTL | `TtlMigrator` shortens the per-provider TTL prediction; shrinks placement weight | I4 |
| F16 | Operator publishes "no automation" / shutdown notice | external signal (manually surfaced) | manual deregistration via CLI; soft-deprecation flow; existing chunks migrate via repair | R6 |
| F17 | Idempotent retry produces 2 handles (real-world common) | dispatcher saw retry succeed; comparing post-write inventory | shadow-register the duplicate immediately | I5 |
| F18 | Provider's `cached_elsewhere_risk` flips from Low → High (operator changes CDN policy) | `health()` reports new value | re-evaluate placement; rotate confidentiality-sensitive chunks elsewhere | I1 by inheritance |
| F19 | Two providers same `provider_id` (misconfigured) | metadata layer | error at registration; engine refuses to start | n/a |
| F20 | Trust correlation group collapses (catbox + litterbox both down) | health pattern across same-operator providers | repair triggers cross-group migration; fewer trust groups available means EC scheme dynamic-resizes | I3 |
| F21 | Per-account throttle vs. per-IP throttle ambiguity | observed retry-after exceeds expected per-IP budget | `AbuseSensor` adopts per-account model; `AccountRotator` rotates earlier | F2 |
| F22 | Net-new put loop (always-failing primary causes thrash) | dispatcher attempts > 5 in 1 min on same shard | shard temporarily marked `Stuck`; supervisor inspects; alert | R6 |
| F23 | Slot reuse race (two writers claim same Forgotten slot) | slot manager | optimistic-CAS on `slot.state`; loser allocates fresh | R4 |
| F24 | Slot-update window expired between bind and write | dispatcher sees `Update` returns "not in window" | fall through to fresh allocation; old slot becomes Frozen | R5 |
| F25 | Crypto-erasure overwrite fails mid-call (network drop) | dispatcher | retry; if persistent, slot stays `Dirty`, shadow remains | I5 |
| F26 | Pack-window times out without filling slot | timer | flush pack as-is; future writes start a new pack | n/a |
| F27 | Geographic outage (one CDN region down, others up) | `egress_geographic_zone` failure cluster | Stage 4 weights toward other zones | I3 |
| F28 | Latency spike on a hot read path | per-op latency moving average | Stage 4 down-weights for `tail_latency_p99`-sensitive reqs; cold path unaffected | soft only |
| F29 | Plugin crash / panic (in-process WASM trap) | `plugin_host` catches | inflight op fails `plugin_resource_error`; `CircuitBreaker.Open`; lifecycle considers restart | I8 |
| F30 | New CA mistrusted (rustls update broke a backend) | TLS error after upgrade | `TlsHealthMonitor` flips; engine warns explicitly that this is *us*, not them | R6 |

---

## §8. Provider Capability Taxonomy — Free-Tier Landscape

This section catalogs the actual free services we can plug in, classified along the §2 axes. The intent: route every chunk to the provider whose declared profile best matches its `PlacementRequest`.

### 8.1 Anonymous file hosts (binary-tolerant)

| Provider | size | retention | update | delete | cas | cached_elsewhere | automation_risk |
|---|---|---|---|---|---|---|---|
| **catbox.moe** | 200 MiB | persistent | None | auth-only | EventualOnly | Low | Tolerated |
| **litterbox.catbox.moe** | 1 GiB | 1h–72h | None | TTL only | EventualOnly | Low | Tolerated |
| **uguu.se** | 128 MiB | 3 h | None | None | EventualOnly | Low | Tolerated |
| **0x0.st** | 512 MiB | 30–365 d | None | X-Token header | EventualOnly | Low | **Forbidden** (operator stated 2026) |
| **x0.at** | 256 MiB | similar to 0x0 | None | possibly via mgmt URL | EventualOnly | Low | Tolerated |
| **bashupload.com** | 50 GiB | 3 d | None | None | EventualOnly | Low | Tolerated *(TLS expired)* |
| **temp.sh** | 4 GiB | 3 d | None | None | EventualOnly | Low | Tolerated *(API broken)* |
| **oshi.at** | 5 GiB | configurable | None | mgmt URL | EventualOnly | Low | Tolerated *(cert/redirect)* |
| **pixeldrain** | 20 GiB | 30 d inactivity | None | with API key | EventualOnly | Low | Tolerated *(now requires auth)* |
| **gofile.io** | large | 10 d inactivity | None | None | EventualOnly | Low | Tolerated *(download requires Premium)* |

### 8.2 Anonymous file hosts (encrypted-by-design)

| Provider | size | retention | update | delete | notes |
|---|---|---|---|---|---|
| Send (TimVisee fork e.g. `send.vis.ee`) | 1 GiB | 7 d / 100 dl | None | with mgmt token | client-side encrypted; their encryption nests under ours |
| Lufi (e.g. `upload.disroot.org`) | ~2 GiB | 30 d | None | with mgmt token | client-side encrypted |

### 8.3 Pastebins (text-only — needs §10.2 wrapper)

| Provider | size | retention | update | content shape |
|---|---|---|---|---|
| paste.rs | ~64 KiB | persistent | None | text only |
| 0bin.net | 10 MiB | configurable | None | text only |
| pastebin.com | 512 KiB | configurable | None | text only |
| dpaste.org | 1 MiB | up to 365 d | None | text only |

### 8.4 Image hosts (ContentSniffing — needs §10.3 PNG wrapper)

| Provider | size | retention | update | rate limit | notes |
|---|---|---|---|---|---|
| Imgur | 20 MiB / image | persistent (account) | replace | ~1250/hr/Client-ID | Tier-F automation risk; ToS |
| ImgBB | 32 MiB / image | configurable | None | per API key | requires API key |
| Postimages | 32 MiB / image | configurable | None | None | anonymous OK |

### 8.5 Code-hosting (git-backed; **TrueUpdate**)

| Provider | size | retention | update | cas | notes |
|---|---|---|---|---|---|
| **GitHub** | 100 MiB / file (LFS) | persistent | **TrueUpdate** | StrongCas (sha + branch) | per-repo soft cap; supports atomic commit |
| **Codeberg** | similar | persistent | **TrueUpdate** | StrongCas | independent operator (good for diversity) |
| **GitLab** | 25 MiB / snippet | persistent | **TrueUpdate** | StrongCas | smaller per-blob cap |

These are **gold for slot pooling**: each file path is a stable handle, true in-place update, full git semantics. CAS for free.

### 8.6 Messaging (each message ≤ 25–50 MiB; **bounded Update window**)

| Provider | size | retention | update | window | notes |
|---|---|---|---|---|---|
| Discord webhooks | 25 MiB / file | persistent (msg lifetime) | edit | 15 min | ~5/sec/webhook |
| Telegram bot | 50 MiB | persistent | edit (text only, not files) | 48 h | per-bot rate limits |
| Slack | 1 GiB | workspace-bound | edit | bounded | requires workspace auth |
| Matrix (homeserver) | 50 MiB typical | federated retention | edit | varies | per-homeserver |
| Mastodon | 40 MiB / image (varies) | federated retention | edit | varies | per-instance |

### 8.7 IPFS pinning (content-addressed; immutable per object)

| Provider | size | retention | update |
|---|---|---|---|
| web3.storage | 30 GiB free | as long as pinned | replace = new CID |
| Pinata | 1 GiB free | as long as pinned | replace = new CID |
| Filebase IPFS | 5 GiB free | as long as pinned | replace = new CID |

Slot pooling does *not* apply at the IPFS layer — by definition each blob is its own CID. But the pinning service's CID-list *can* be slot-pooled on the meta layer (one repinning operation = one slot rewrite).

### 8.8 Cloud free tiers (full S3 semantics; **TrueUpdate + StrongCas**)

| Provider | free tier | update | cas |
|---|---|---|---|
| Cloudflare R2 | 10 GiB storage + 10 GB egress/month | TrueUpdate | StrongCas (etag) |
| Backblaze B2 | 10 GiB storage + 1 GB/day egress | TrueUpdate | StrongCas |
| Filebase S3 | 5 GiB | TrueUpdate (S3 facade, IPFS substrate) | StrongCas |
| Storj | 25 GiB | TrueUpdate | StrongCas |

These are also gold: real S3, no abuse-class issues, predictable quotas. Their problem is they're not *fully* anonymous (account required) — addressed by §6.6 `AccountRotator`.

### 8.9 Edge KV / Blob stores

| Provider | size cap | free tier | update |
|---|---|---|---|
| Cloudflare KV | 25 MiB / value | 1k writes/day, 100k reads/day free | TrueUpdate |
| Vercel Blob | 256 MiB / blob | 1 GiB free | TrueUpdate |
| Netlify Blobs | similar | similar | TrueUpdate |

### 8.10 Forum / community (text + small media; **edit-supporting**)

| Provider | size | retention | update | notes |
|---|---|---|---|---|
| Reddit | 20 MiB image / API | persistent | edit | high abuse-detection risk |
| Mastodon | 40 MiB / instance varies | persistent | edit | federated; per-instance ToS |
| Lemmy | similar | persistent | edit | federated |

### 8.11 Aggregate observations

- The **portfolio's diversity is in the long tail**, not in the head. Six anonymous file hosts have nearly the same capability profile; one S3-compatible adds capabilities the others lack entirely.
- **TrueUpdate-supporting providers** are dominated by (a) git hosting, (b) S3-compatible cloud free tiers, (c) edge KV, (d) bounded-window messaging. Slot pooling targets these.
- **Long-retention permanent + true update** = git hosting and S3. These are the slot-pool's primary substrate.
- **Short-retention + no update** = uguu, litterbox, temp.sh. These are the *high-churn shard* substrate — chunks placed here die and get repaired regularly. The router should *intentionally* place sacrificial / reread-fast chunks here.
- **Rate-limited but reliable** = Imgur, Discord. These suit `Append`-style packing because each "message" carries one shard.

---

## §9. Mathematical Model (informal)

### 9.1 The placement objective

For each chunk write, given pool $P$ and request $r$:

$$
\arg\min_{S \subseteq P, |S|=n} \sum_{p \in S} \text{cost}(p, r) \quad \text{s.t.} \\
\quad \forall p \in S: \text{eligible}(p, r) \\
\quad \forall p_i, p_j \in S, i \neq j: \text{group}(p_i) \neq \text{group}(p_j) \\
\quad |S| \geq w
$$

`cost(p, r)` is the §4.4 cost vector reduced via the operator's L1 weights.

### 9.2 Slot pool's effect on the objective

If the slot pool yields a candidate slot $s^*$ that satisfies the eligibility predicate, replace one element of $S$ with that slot, charging only the *update* cost (zero for new bytes-stored, marginal for op-count) instead of the *fresh-allocation* cost.

This is the source of the slot pool's win: $\text{cost}_\text{update} \ll \text{cost}_\text{fresh}$ for the providers that support it.

### 9.3 Why this is tractable in practice

Pool sizes are tens, not millions. The constraint solver runs in $O(n \cdot |P|)$ per chunk. Caching the eligibility predicate per-chunk-class amortizes most of the work.

---

## §10. Smart Tricks — beyond slot reuse

### 10.1 Account rotation (token pools)

§6.6. Multiplies effective rate × N by holding N anonymous accounts behind one provider entry. Requires: declared `RequiresAccount`, declared `account_pool_strategy`, and a `Vec<CredentialsHandle>` in metadata.

### 10.2 Text-only adapter

For pastebins, wrap shard ciphertext in a base64 envelope with a length prefix. Trivially round-trippable. Done already in `os-plugin-paste-rs`. Generalize as `PluginContract::content_shape_adapter() -> Adapter` so the host wraps automatically without each plugin reimplementing.

### 10.3 Image-only adapter (PNG steganography)

For image hosts (Imgur, ImgBB), wrap shard ciphertext as a 1×N or √N×√N PNG. The host inspects pixels, accepts. On read, decode the PNG and unpack the byte array. Adds ~5–10 % overhead. Standard technique.

### 10.4 Append-pack / log-structured slot

For backends that allow `Append` within a window, treat a slot as a *log* of `(seq_no, length, ciphertext)` records. Reads scan the log; writes append. Periodically `Update` the slot to compact (drop deleted records). Effective on Discord webhooks (15 min edit window aligns with packing window) and Telegram bot text-message edits.

### 10.5 Geographic diversity bonus

Soft objective in Stage 4. Two backends in different regions, all else equal, score higher than two in the same region. Resists region-wide outages without requiring formal multi-region semantics.

### 10.6 Time-of-day routing

Some services have 24-hour windows that reset at midnight UTC. Stage 2's `AbuseSensor` can predict the rollover and bias toward providers whose window has just reset. Useful when total daily portfolio capacity is bounded.

### 10.7 Latency-class routing

Hot (user-facing) reads have a `deadline`. Stage 4 weights `tail_latency_p99` 10× for these. Cold (scrub, anti-entropy) reads weight `dollar_cost` 10× and tolerate latency.

### 10.8 EC-aware repacking (cold migration)

Background repair can rewrite a chunk's shards from `(k=1, n=2)` (replication on small pool) to `(k=4, n=7)` (parity coding) once the pool grows. The repair scheduler emits `PlacementRequest` with `previous_assignment` so slot pools rebind cleanly.

### 10.9 Cross-trust-group fallback (already in §4.6)

The single most-important change to the existing `PoolDispatcher`: dispatcher reroutes across trust groups when same-group fallback is empty. Honoring R1 means tracking `used_groups` across the entire chunk's shard set, not per-shard-call.

### 10.10 Probe-driven discovery

When a brand-new provider profile is registered, the engine runs a *conformance probe* (small put, peek, get, delete, repeat under load) before placing real shards. The result populates the actual `RateLimitProfile` and capability flags from observation, not declaration. Closes `RESILIENCE.md` §2.A.2 ("plugin lies about capabilities"). Ties into `STRUCTURAL_REWORK.md` Layer 5 (real-test conformance).

### 10.11 Chunk-class-aware sizing

The slot pool defaults to power-of-two size classes (`128 KiB, 256 KiB, …, 256 MiB`). For workloads with bimodal sizing (lots of 4 KiB metadata + lots of 4 MiB media), classes can be tuned. Avoids fragmentation.

### 10.12 CAS-delegated coordination

Per `STRUCTURAL_REWORK.md` Layer 3, snapshot pointers and leases live only on `StrongCas` providers. The router enforces this in Stage 1 (eligibility filter, R3). When fewer than 1 StrongCas provider exists, coordination falls back to a `OptimisticCas` quorum-of-three. When fewer than three exist, the engine refuses to write coordination and surfaces the gap.

### 10.13 Capability-arbitrage routing

A chunk's request may declare `mutability_intent = UpdatableSlot`. If no Update-capable provider is eligible (cost too high, all quarantined, etc.), the router falls back to the immutable path *but* records the chunk's preference so a later `TtlMigrator` / `cold migration` cycle moves it to a slot-capable provider when one becomes available. Soft preferences are persisted, not lost.

### 10.14 Trust-correlation transitive closure

Two distinct providers may share infrastructure not obvious from their `trust_correlation_group` (catbox + litterbox). The design encodes a *graph* where edges are "shared operator" / "shared CDN" / "shared egress." The diversity rule operates over the graph's transitive closure, not just direct labels. Built once, queried per placement.

---

## §11. What's broken today (Concrete Audit)

Linking the design to the current code so the migration plan in §13 has clear targets.

| Gap | Where | Today | Design (§) |
|---|---|---|---|
| `chunk_bytes` not consulted at placement | [`src/placement/src/lib.rs:141`](./src/placement/src/lib.rs) | `pick_shards_for_chunk` doesn't accept it | §4.1 |
| `max_object_bytes` ignored in weight | [`src/placement/src/lib.rs:209`](./src/placement/src/lib.rs) | `compute_weight` reads quota, health, tier_match, user_weight only | §4.1, §4.4 |
| Capability flags stored but unread | [`src/placement/src/lib.rs:38`](./src/placement/src/lib.rs) | `PoolEntry.capabilities` is set but no consumer | §4.1 |
| Cross-group fallback absent | [`src/vfs/src/lib.rs:561`](./src/vfs/src/lib.rs) | candidate list = `[primary] + same-group siblings` | §4.6, §10.9 |
| No periodic health refresh | n/a | `Provider.health` is frozen at registration | §6.1 |
| `max_rate_limit_wait = None` default | [`src/plugin_host/src/rate_limit.rs:158`](./src/plugin_host/src/rate_limit.rs) | a 1h Retry-After blocks the put for 1h | §4.6 |
| Slot pool absent | n/a | every put = new handle, even on Update-capable providers | §5 |
| `AccountRotator` absent | n/a | one provider = one account; rate ceilings are per-account | §6.6 |
| `AbuseSensor` absent | n/a | no daily budget enforcement | §6.3 |
| `CircuitBreaker` partial | [`src/plugin_host/src/host.rs:53`](./src/plugin_host/src/host.rs) | `HealthMonitor` records errors but no formal Open/HalfOpen/Closed transitions | §6.2 |
| `IdempotencyTracker` absent | n/a | no learning from observed-vs-declared idempotency drift | §6.5 |
| `PlacementRequest` doesn't exist | n/a | placement input is too narrow | §3 |
| `ContentShape` adapter not pluggable | each plugin reimplements (paste-rs base64s, image plugins TBD) | not unified | §10.2, §10.3 |

---

## §12. Test Plan — baseline tests, layer by layer

Following `STRUCTURAL_REWORK.md`'s layer/baseline pattern. Each layer earns the right to be called "done" by a single end-to-end baseline test that goes red→green.

### Layer R0 — `PlacementRequest` plumbed end-to-end

`cli/tests/routing_request_threaded.rs`: write a 1 MiB chunk; assert that the placement decision has access to `chunk_bytes=1_048_576` (verify by registering a provider with `max_object_bytes=512_000` and asserting it is *not* picked, where today it would be picked and the put would fail).

### Layer R1 — Eligibility filter with size cap

`cli/tests/routing_size_cap.rs`: register paste.rs (64 KiB cap) + catbox (200 MiB) + uguu (128 MiB); write a 2 MiB chunk; assert the chunk is split across catbox + uguu (paste.rs filtered out at Stage 1).

### Layer R2 — `SupplierHealthWatcher` auto-refresh

`cli/tests/routing_health_refresh.rs`: register a `MockPlugin` whose `health()` returns `Healthy` for 3 calls then `Unhealthy`; with `health_interval=200ms`, assert that within 1 s the engine has marked the provider `Unhealthy` and stops placing on it without any explicit user action.

### Layer R3 — Cross-group fallback

`cli/tests/routing_cross_group_fallback.rs`: register 4 providers in 4 distinct trust groups; mark the primary `RateLimited`; assert the put succeeds via cross-group overflow without a stall.

### Layer R4 — Slot pool: same-owner update

`cli/tests/routing_slot_same_owner.rs`: register a `MockUpdatePlugin` (TrueUpdate); write a chunk; rewrite the same chunk; assert the second write does *not* allocate a new handle (handle byte-equality), and the shadow registry is empty.

### Layer R5 — Slot pool: rebind-after-forget

`cli/tests/routing_slot_rebind.rs`: write chunk A; delete A (slot becomes Forgotten); write chunk B at the same size class; assert B reuses A's slot (handle byte-equality), and the shadow registry is empty.

### Layer R6 — Crypto-erasure on delete-unsupported provider

`cli/tests/routing_crypto_erasure.rs`: register a `TrueUpdate, no-Delete` mock; write chunk A; delete A; assert the slot's bytes-at-rest are random (no AEAD tag), key dropped, slot state is `Empty`.

### Layer R7 — `AbuseSensor` daily budget

`cli/tests/routing_abuse_budget.rs`: register a provider with `daily_op_budget=10`; write 10 chunks with single-shard scheme; assert the 11th routes *elsewhere* without the provider returning any error.

### Layer R8 — `AccountRotator`

`cli/tests/routing_account_rotation.rs`: register a `RequiresAccount` mock with 3 token pool; saturate token 1's rate budget; assert the next put rotates to token 2 transparently.

### Layer R9 — `CapabilityDriftDetector`

`cli/tests/routing_capability_drift.rs`: register a provider declaring `Delete`; mock the plugin to return `NotSupported` from `delete()`; assert that within 60 s the engine's view of the capability is updated to `NotSupported` and subsequent deletes don't try.

### Layer R10 — Probe-driven conformance discovery

`cli/tests/routing_conformance_probe.rs`: register a brand-new provider with mock `RateLimitProfile.puts.per_sec=100`; mock the actual rate limit at 1/sec; after probe, assert the engine's effective rate matches observation (1/sec), not declaration.

These baseline tests are designed to run *without* live external services (they use the existing `os-plugin-fault-inject` and a new `os-plugin-mock-update` family) so they're CI-friendly. Live integration with §8's real services is *additional* coverage layered on top of these baselines, not a substitute.

---

## §13. Migration Plan — staged, never-red

The current workspace is at 238 passing tests, 0 failing. The migration must keep that property at every step.

### Step 1 — Introduce `PlacementRequest` (compile-only change)

- Add `PlacementRequest` struct.
- Refactor `pick_shards_for_chunk` to accept `&PlacementRequest` rather than `(chunk_hash, scheme, …)`.
- Existing call sites pass a hand-built request with `chunk_bytes` and reasonable defaults for the other fields.
- All existing tests pass unchanged.

### Step 2 — Promote `PoolEntry`

- Add `max_object_bytes: Option<u64>`, `cas_tier`, `update_capability`, `automation_risk`, etc. to `PoolEntry`.
- `PoolSnapshot::from_providers` populates them from the existing `Provider` fields where possible.
- Add Stage 1 eligibility filter; today it's a no-op (passes all). Layer R0 baseline goes green.

### Step 3 — Implement `SupplierHealthWatcher`

- New worker in the supervisor crate.
- Layer R2 baseline goes green.
- Existing `HealthMonitor` continues to function unchanged.

### Step 4 — `max_object_bytes` enforcement at Stage 1

- Eligibility predicate now actually filters.
- Add Layer R1 baseline; goes green.

### Step 5 — `max_rate_limit_wait = Some(30s)` default

- One-line change.
- Re-run full suite (some live-test thresholds may need adjustment); document any drift.

### Step 6 — Cross-group fallback

- Modify `vfs::persist_chunk` candidate construction to extend with cross-group overflow.
- Layer R3 baseline goes green.
- Verify EC determinism unchanged for happy paths.

### Step 7 — Slot pool, single-provider scope

- Slot manager + persistence.
- Implement only `Update` path; `Append` and packing come later.
- Wire in `vfs` as a Stage 3 hook.
- Layers R4, R5 go green.

### Step 8 — Crypto-erasure

- Layer R6 goes green.

### Step 9 — `CircuitBreaker` formalization

- Promote `HealthMonitor`'s ad-hoc tracking to per-(provider, op) state machine.
- No new baseline (existing Layer 2 test from `STRUCTURAL_REWORK.md` already covers ban/recovery; this strengthens it).

### Step 10 — `AbuseSensor`

- New subsystem, Layer R7 green.

### Step 11 — `AccountRotator`

- New subsystem, Layer R8 green.

### Step 12 — `CapabilityDriftDetector`, `IdempotencyTracker`

- Layers R9, R10 green.

### Step 13 — Pack-and-unpack

- After the slot pool is mature.
- New baseline (R11): bimodal-size workload metadata budget stays within FUTURE_IMPROVEMENTS.md §1's 15 GiB cap.

### Step 14 — Probe-driven conformance

- Layer R10 green.

Each step is a separate PR with its own baseline test. No step lands without baseline-green.

---

## §14. Open Questions / Risks

1. **Is the Pareto-front pruning in Stage 4 worth the complexity?** A simpler weighted-sum may be enough. We'll know after Layer R4 — if its baseline lands without using Pareto, simplify.
2. **Cross-group fallback weakens R1 in degraded mode.** When we fall back to a non-canonical group, we briefly may have *fewer* than `n` distinct groups. The repair scheduler must catch up. Risk: if repair is slow, the chunk is undiverse for a window. Mitigation: emit explicit `placement.diversity_reduced` events so users see this.
3. **Slot pool persistence cost.** Slots are persisted in metadata; a portfolio of 20 providers × 1000 slots/provider = 20k records. Probably negligible against the 50M-chunk metadata budget but worth measuring.
4. **Crypto-erasure on `AtomicReplace`-only providers.** As noted in §5.5, this requires `TrueUpdate`. For `AtomicReplace` providers, erasure-via-overwrite still helps (the new bytes are random) but creates a fresh shadow. Not a clean win. Decision: only enable crypto-erasure path on declared `TrueUpdate` providers.
5. **`AccountRotator` and ToS.** Multi-account rotation against a single service may itself be a ToS violation. The design surfaces `automation_risk_class=Forbidden` providers and refuses to rotate against them by default.
6. **Probe-driven discovery vs. cold start.** Conformance probes against a fresh service take time and cost ops budget. For a freshly-added provider, we probe at low priority before promoting it to first-class placement.
7. **The slot pool's invariant: "Forgotten slot's bytes are unreachable plaintext."** If the prior owner's chunk key was leaked before the erasure overwrite happened, the bytes are still readable. This is a *narrow* window (between owner-release and erasure-overwrite). The design treats this as residual risk and recommends erasure run synchronously on release whenever the provider supports `TrueUpdate`.
8. **Capability arbitrage edge case.** If *no* Update-capable provider is eligible, slot-intent chunks are placed immutably with a "wants slot when available" marker. The migrator picks them up later. Risk: if the operator never adds a slot-capable provider, the marker accumulates. Decision: GC the marker after `migration_pending_max_age` (default 90 d).
9. **Test infrastructure cost.** §12's 11 baseline tests are non-trivial to write (each needs a tailored mock plugin). Justified by the routing layer being the engine's value; cheap routing = cheap correctness arguments later.
10. **The matrix in §7 is not formally complete.** It's a best-effort enumeration. New failure modes will surface in production. The design accommodates this by making detector + responder + invariant the unit of extension; new rows are added without disturbing existing ones.

---

## §15. Acceptance Criteria

This design is "production-ready" — the bar the user named at the start of this session — when:

1. All §12 baseline tests pass on CI on every commit.
2. The §11 audit table is empty (every "today" is fixed).
3. A live integration suite running daily against §8.1, §8.5, §8.8 demonstrates that **placement chooses the right provider for each request class** (size, mutability, lifetime) more than 99 % of the time over a 7-day window.
4. The portfolio test in `STRUCTURAL_REWORK.md` Layer 5 succeeds against ≥10 distinct trust groups, with simulated outages of 30 % of providers, without losing any chunk.
5. The matrix in §7 has explicit baseline coverage for ≥80 % of rows; the rest are explicitly accepted as residual risk in §14.

Every claim in this document is testable. Every test is layered. Every layer earns its color from a red→green transition, not from compile success.
