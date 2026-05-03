//! os-placement — pure shard placement.
//!
//! Given a `PoolSnapshot` and a `PlacementRequest`, returns a
//! deterministic `ProviderId` per shard. No I/O. The L4 caller fetches
//! the pool from `os-vault::current_pool()` and constructs the request.
//!
//! See `ROUTING.md` §3 for the full rationale behind `PlacementRequest`
//! and §13 for the staged migration this lives inside.

#![forbid(unsafe_code)]

use os_entities::Provider;
use os_types::{
    CapabilitySet, CasTier, ChunkHash, ECScheme, HealthScore, ProviderId, Tier,
    TrustCorrelationGroup, UpdateCapability,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlacementError {
    #[error("placement impossible: pool has no providers with required capabilities")]
    Impossible,
    #[error("not enough distinct trust groups: have {have}, need {need}")]
    InsufficientGroups { have: usize, need: usize },
    #[error("placement impossible: chunk size {chunk_bytes} exceeds every eligible provider's max_object_bytes")]
    SizeExceedsAllCaps { chunk_bytes: u64 },
}

/// What the chunk is for. Drives role-aware filtering (e.g., snapshot
/// pointers require `StrongCas` or quorum-of-three `OptimisticCas`; chunk
/// shards don't).
///
/// Defaults to `Chunk` so callers that don't yet need role-awareness keep
/// working unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChunkRole {
    #[default]
    Chunk,
    SnapshotPointer,
    Lease,
    Share,
    Identity,
    Coordination,
}

/// Read/write pattern hint. Today: informational only. Later: drives
/// Stage-4 cost weighting (hot reads get tail-latency budget; cold get
/// dollar-cost budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessPattern {
    #[default]
    Standard,
    ReadMostly,
    WriteOnce,
    RewriteFrequent,
    Hot,
}

/// How precious this chunk is. Today: informational. Later: gates EC
/// scheme selection (Critical may force higher n; Sacrificial may allow
/// smaller k).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedundancyClass {
    #[default]
    Standard,
    Critical,
    Sacrificial,
}

/// Expected duration the chunk needs to remain retrievable. Used by the
/// (future) `TtlMigrator` to schedule re-placement before retention cliffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExpectedLifetime {
    #[default]
    Persistent,
    Bounded { days: u32 },
    Unknown,
}

/// Whether the engine plans to rewrite this chunk's bytes again. The
/// slot-pool subsystem (ROUTING.md §5) consults this to bind to an
/// Update-capable provider where possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MutabilityIntent {
    #[default]
    Immutable,
    UpdatableSlot,
    Append,
}

/// Wire-format the chunk arrives in. `Opaque` is the engine default
/// (already-encrypted, already-encoded, arbitrary binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentShape {
    #[default]
    Opaque,
    TextOnly,
    ImageWrapped,
}

/// Confidentiality bar. `Standard` accepts any backend; `NoCachedElsewhere`
/// excludes high-cache-risk providers (Imgur, archive.org); `Sovereign`
/// further excludes anything outside the user's chosen jurisdictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfidentialityClass {
    #[default]
    Standard,
    NoCachedElsewhere,
    Sovereign,
}

/// What was placed previously when a chunk is being re-placed (repair,
/// migration). Lets the slot pool re-bind the same slot identity.
#[derive(Debug, Clone)]
pub struct PriorAssignment {
    pub provider_id: ProviderId,
    pub slot_id: Option<u64>,
}

/// **The full input to placement.** Replaces the prior bag of positional
/// arguments. New fields default to "no constraint"; only `chunk_hash`,
/// `chunk_bytes`, and `scheme` are typically caller-supplied today.
///
/// See ROUTING.md §3 for field-by-field semantics.
#[derive(Debug, Clone)]
pub struct PlacementRequest {
    pub chunk_hash: ChunkHash,
    pub chunk_bytes: u64,
    pub scheme: ECScheme,
    pub tier: Tier,
    pub role: ChunkRole,
    pub access_pattern: AccessPattern,
    pub redundancy_class: RedundancyClass,
    pub expected_lifetime: ExpectedLifetime,
    pub mutability_intent: MutabilityIntent,
    pub content_shape: ContentShape,
    pub trust_required: ConfidentialityClass,
    pub deadline: Option<std::time::Instant>,
    pub previous_assignment: Option<PriorAssignment>,
}

impl PlacementRequest {
    /// Construct a basic chunk-write request with all advisory fields at
    /// their defaults. Used by today's `vfs::persist_chunk` path; richer
    /// callers (snapshot, repair) construct directly with explicit fields.
    pub fn for_chunk(chunk_hash: ChunkHash, chunk_bytes: u64, scheme: ECScheme) -> Self {
        Self {
            chunk_hash,
            chunk_bytes,
            scheme,
            tier: Tier::Hot,
            role: ChunkRole::default(),
            access_pattern: AccessPattern::default(),
            redundancy_class: RedundancyClass::default(),
            expected_lifetime: ExpectedLifetime::default(),
            mutability_intent: MutabilityIntent::default(),
            content_shape: ContentShape::default(),
            trust_required: ConfidentialityClass::default(),
            deadline: None,
            previous_assignment: None,
        }
    }
}

/// Snapshot of the placement-relevant state for one pool. Built by
/// `os-vault::current_pool()`.
#[derive(Debug, Clone)]
pub struct PoolSnapshot {
    pub providers: Vec<PoolEntry>,
}

#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub provider_id: ProviderId,
    pub trust_group: TrustCorrelationGroup,
    pub health: HealthScore,
    pub remaining_quota: Option<u64>,
    pub tier_match: f32,
    pub user_weight: f32,
    pub capabilities: CapabilitySet,
    /// Per-object byte ceiling declared by the plugin's
    /// `rate_limit_profile().max_object_bytes`. `None` = unknown, treated
    /// as "no constraint" (conservative for liveness, costly for
    /// correctness — that's why Step 4 activates a strict filter once
    /// values are populated reliably).
    pub max_object_bytes: Option<u64>,
    /// Compare-and-swap capability the plugin offers. `None` = caller
    /// declined to populate (treated as `EventualOnly` for any check that
    /// needs strong CAS).
    pub cas_tier: Option<CasTier>,
    /// Whether this provider's backend supports overwrite. Drives the
    /// slot-pool subsystem's decision to attempt `plugin.update()`.
    /// Defaults to `None` for safety (no slot reuse) so plugins that
    /// haven't opted in are unaffected.
    pub update_capability: UpdateCapability,
}

/// Host-side profile bits (declared by the loaded plugin, not the
/// persisted `Provider` record). `PoolSnapshot::enrich` consumes a
/// closure of this type so the placement crate stays decoupled from
/// `plugin_host`.
#[derive(Debug, Clone, Default)]
pub struct HostProfile {
    pub max_object_bytes: Option<u64>,
    pub cas_tier: Option<CasTier>,
    pub update_capability: UpdateCapability,
}

impl PoolSnapshot {
    /// Build a snapshot from persisted `Provider` records. Host-side
    /// fields (`max_object_bytes`, `cas_tier`) default to `None`; call
    /// `enrich` to populate them from the live plugin's profile.
    pub fn from_providers(providers: &[Provider]) -> Self {
        let entries = providers
            .iter()
            .map(|p| PoolEntry {
                provider_id: p.provider_id,
                trust_group: p.trust_correlation_group.clone(),
                health: p.health,
                remaining_quota: p.quota.total.and_then(|t| {
                    p.quota.used.map(|u| t.saturating_sub(u))
                }),
                tier_match: 1.0,
                user_weight: 1.0,
                capabilities: p.capabilities.clone(),
                max_object_bytes: None,
                cas_tier: None,
                update_capability: UpdateCapability::None,
            })
            .collect();
        Self { providers: entries }
    }

    /// Populate host-side fields by querying a per-provider closure. The
    /// caller (typically `os-vault`) holds the `Host` and converts its
    /// `RateLimitProfile` into a `HostProfile`.
    pub fn enrich<F>(&mut self, profile_for: F)
    where
        F: Fn(ProviderId) -> HostProfile,
    {
        for entry in &mut self.providers {
            let prof = profile_for(entry.provider_id);
            entry.max_object_bytes = prof.max_object_bytes;
            entry.cas_tier = prof.cas_tier;
            entry.update_capability = prof.update_capability;
        }
    }
}

/// **Stage-1 eligibility filter** (ROUTING.md §4.1).
///
/// Returns the subset of the pool that is *eligible* for the given
/// request. Today's predicate is intentionally permissive — only
/// `max_object_bytes`-vs-`chunk_bytes` is checked, and only when the
/// plugin actually declared a ceiling. Other gates (CAS tier, content
/// shape, trust class) light up in subsequent steps of §13.
///
/// Pure function, no I/O. Returning a fresh `PoolSnapshot` keeps
/// downstream stages oblivious to whether they got the original pool or
/// a filtered one.
pub fn eligibility_filter(req: &PlacementRequest, pool: &PoolSnapshot) -> PoolSnapshot {
    let entries: Vec<PoolEntry> = pool
        .providers
        .iter()
        .filter(|p| {
            // Hard size gate (R2). `None` = unknown: passes through, on
            // the assumption that the plugin will surface an out-of-range
            // error if violated. Step 4 narrows this further.
            match p.max_object_bytes {
                Some(cap) => req.chunk_bytes <= cap,
                None => true,
            }
        })
        .cloned()
        .collect();
    PoolSnapshot { providers: entries }
}

#[derive(Debug, Clone, Copy)]
pub struct DiversityPolicy {
    /// Hard requirement: distinct trust groups for distinct shards.
    pub require_distinct_trust_groups: bool,
    /// Soft preference: spread across legal classes (best-effort).
    pub prefer_legal_diversity: bool,
}

impl Default for DiversityPolicy {
    fn default() -> Self {
        Self {
            require_distinct_trust_groups: true,
            prefer_legal_diversity: true,
        }
    }
}

/// Caller-supplied targets for dynamic EC selection.
///
/// Per RESILIENCE.md §3.2:
///
/// ```text
/// available_groups = distinct trust-correlation groups in healthy plugin pool
/// N_max            = max practical (capped by config; default 13)
/// K_target         = config.redundancy.k (default 4)
/// N_chosen         = min(available_groups, N_max)
/// if N_chosen < K_target + 1:
///   fall back to replication mode (replication_factor = available_groups)
/// else:
///   EC scheme = (K_target, N_chosen)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct EcTargets {
    pub k_target: u8,
    pub n_max: u8,
}

impl Default for EcTargets {
    fn default() -> Self {
        // Engine default keeps `k_target=1` so deployments with a small
        // pool transparently get replication. Operators with ≥5 distinct
        // trust groups should bump `k_target` to 4 (the design's spec
        // default) for storage-efficient parity coding.
        Self { k_target: 1, n_max: 13 }
    }
}

/// Pick the EC scheme for a *new* chunk write given the live pool. The
/// chosen scheme is recorded on the Chunk record; mixed schemes coexist.
///
/// Returns `(1, 1)` only when the pool has exactly one distinct trust
/// group — that's an explicit single-copy mode (no redundancy possible).
/// Otherwise the function picks the most resilient scheme the pool can
/// sustain.
pub fn select_ec_scheme(pool: &PoolSnapshot, targets: EcTargets) -> ECScheme {
    let mut groups: std::collections::BTreeSet<&TrustCorrelationGroup> =
        std::collections::BTreeSet::new();
    for p in &pool.providers {
        groups.insert(&p.trust_group);
    }
    let available = groups.len() as u8;
    if available == 0 {
        // Caller will bail at placement time anyway; emit something safe.
        return ECScheme { k: 1, n: 1 };
    }
    let n_chosen = available.min(targets.n_max).max(1);
    let k_target = targets.k_target.max(1);
    if n_chosen < k_target.saturating_add(1) {
        // Replication: k=1, n=available. Tolerates n-1 losses.
        ECScheme { k: 1, n: n_chosen }
    } else {
        // Parity-coded EC: (k_target, n_chosen). Tolerates n-k losses.
        ECScheme {
            k: k_target,
            n: n_chosen,
        }
    }
}

/// Choose `(shard_index, ProviderId)` for each shard of a chunk.
///
/// New API: takes a full `PlacementRequest`. The legacy positional form is
/// available via `PlacementRequest::for_chunk` + this function — callers
/// migrating step-by-step should use that builder.
pub fn pick_shards_for_chunk(
    req: &PlacementRequest,
    pool: &PoolSnapshot,
    diversity: DiversityPolicy,
) -> Result<Vec<(u8, ProviderId)>, PlacementError> {
    let n = req.scheme.n as usize;
    if pool.providers.is_empty() {
        return Err(PlacementError::Impossible);
    }
    if diversity.require_distinct_trust_groups {
        let groups: std::collections::BTreeSet<_> = pool
            .providers
            .iter()
            .map(|p| p.trust_group.clone())
            .collect();
        if groups.len() < n {
            return Err(PlacementError::InsufficientGroups {
                have: groups.len(),
                need: n,
            });
        }
    }
    let mut out = Vec::with_capacity(n);
    let mut used_groups = std::collections::BTreeSet::new();
    for shard_index in 0..n as u8 {
        let pick = best_pick(req.chunk_hash, shard_index, pool, &used_groups, &diversity)
            .ok_or(PlacementError::Impossible)?;
        if diversity.require_distinct_trust_groups {
            used_groups.insert(pick.trust_group.clone());
        }
        out.push((shard_index, pick.provider_id));
    }
    Ok(out)
}

fn best_pick<'a>(
    chunk_hash: ChunkHash,
    shard_index: u8,
    pool: &'a PoolSnapshot,
    used_groups: &std::collections::BTreeSet<TrustCorrelationGroup>,
    diversity: &DiversityPolicy,
) -> Option<&'a PoolEntry> {
    let mut best: Option<(f64, &PoolEntry)> = None;
    for p in &pool.providers {
        if diversity.require_distinct_trust_groups && used_groups.contains(&p.trust_group) {
            continue;
        }
        let weight = compute_weight(p);
        if weight <= 0.0 {
            continue;
        }
        let h = consistent_hash(chunk_hash, shard_index, p.provider_id);
        // CRUSH-style: score = -ln(rand)/weight, lowest wins. We use the hash
        // as a stand-in for `rand`.
        let r = (h as f64 + 1.0) / (u64::MAX as f64 + 2.0);
        let score = -r.ln() / weight;
        match best {
            None => best = Some((score, p)),
            Some((bs, _)) if score < bs => best = Some((score, p)),
            _ => {}
        }
    }
    best.map(|(_, p)| p)
}

fn compute_weight(p: &PoolEntry) -> f64 {
    let quota = p.remaining_quota.unwrap_or(u64::MAX) as f64;
    let quota_factor = (quota / (1.0 + quota)).clamp(0.0, 1.0);
    let h = p.health.value() as f64;
    let tm = p.tier_match as f64;
    let uw = p.user_weight as f64;
    quota_factor * h * tm * uw
}

fn consistent_hash(chunk_hash: ChunkHash, shard_index: u8, pid: ProviderId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(chunk_hash.as_bytes());
    hasher.update(&[shard_index]);
    hasher.update(pid.as_uuid().as_bytes());
    let h = hasher.finalize();
    let bytes = h.as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(group: &str) -> PoolEntry {
        PoolEntry {
            provider_id: ProviderId::new_v7(),
            trust_group: TrustCorrelationGroup::new(group),
            health: HealthScore::new(1.0),
            remaining_quota: Some(1_000_000),
            tier_match: 1.0,
            user_weight: 1.0,
            capabilities: CapabilitySet::default(),
            max_object_bytes: None,
            cas_tier: None,
            update_capability: UpdateCapability::None,
        }
    }

    fn entry_with_cap(group: &str, cap: u64) -> PoolEntry {
        let mut e = entry(group);
        e.max_object_bytes = Some(cap);
        e
    }

    #[test]
    fn distinct_groups_assigned() {
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b"), entry("c"), entry("d")],
        };
        let scheme = ECScheme::new(2, 3).unwrap();
        let req = PlacementRequest::for_chunk(ChunkHash::from_bytes([1u8; 32]), 1024, scheme);
        let picks = pick_shards_for_chunk(&req, &pool, DiversityPolicy::default()).unwrap();
        assert_eq!(picks.len(), 3);
        let groups: std::collections::HashSet<_> = picks
            .iter()
            .map(|(_, pid)| {
                pool.providers
                    .iter()
                    .find(|p| p.provider_id == *pid)
                    .unwrap()
                    .trust_group
                    .clone()
            })
            .collect();
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b"), entry("c"), entry("d")],
        };
        let scheme = ECScheme::new(2, 3).unwrap();
        let req = PlacementRequest::for_chunk(ChunkHash::from_bytes([7u8; 32]), 1024, scheme);
        let a = pick_shards_for_chunk(&req, &pool, DiversityPolicy::default()).unwrap();
        let b = pick_shards_for_chunk(&req, &pool, DiversityPolicy::default()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn placement_request_carries_chunk_bytes() {
        // Layer R0 baseline (ROUTING.md §13 Step 1): the request type
        // exposes chunk size to placement. Stages that filter on it (Step
        // 4) build on this; this test fails if the field disappears.
        let scheme = ECScheme::new(1, 1).unwrap();
        let req =
            PlacementRequest::for_chunk(ChunkHash::from_bytes([0u8; 32]), 4 * 1024 * 1024, scheme);
        assert_eq!(req.chunk_bytes, 4 * 1024 * 1024);
        assert_eq!(req.scheme.k, 1);
        assert_eq!(req.scheme.n, 1);
        assert_eq!(req.role, ChunkRole::Chunk);
        assert_eq!(req.mutability_intent, MutabilityIntent::Immutable);
    }

    #[test]
    fn ec_selection_replication_when_pool_small() {
        // 2 trust groups, default k_target=1: replication(2).
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b")],
        };
        let s = select_ec_scheme(&pool, EcTargets::default());
        assert_eq!((s.k, s.n), (1, 2));
    }

    #[test]
    fn ec_selection_replication_factor_bounded_by_groups() {
        // 5 trust groups, k_target=1: replication(5).
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b"), entry("c"), entry("d"), entry("e")],
        };
        let s = select_ec_scheme(&pool, EcTargets { k_target: 1, n_max: 13 });
        assert_eq!((s.k, s.n), (1, 5));
    }

    #[test]
    fn ec_selection_picks_parity_scheme_when_pool_large() {
        // k_target=4, 7 distinct groups: (4, 7).
        let pool = PoolSnapshot {
            providers: (0..7).map(|i| entry(&format!("g{i}"))).collect(),
        };
        let s = select_ec_scheme(&pool, EcTargets { k_target: 4, n_max: 13 });
        assert_eq!((s.k, s.n), (4, 7));
    }

    #[test]
    fn ec_selection_falls_back_when_groups_below_threshold() {
        // k_target=4, only 4 distinct groups → can't satisfy k+1, fall
        // back to replication(4).
        let pool = PoolSnapshot {
            providers: (0..4).map(|i| entry(&format!("g{i}"))).collect(),
        };
        let s = select_ec_scheme(&pool, EcTargets { k_target: 4, n_max: 13 });
        assert_eq!((s.k, s.n), (1, 4));
    }

    #[test]
    fn ec_selection_caps_at_n_max() {
        // 20 groups but n_max=7: cap.
        let pool = PoolSnapshot {
            providers: (0..20).map(|i| entry(&format!("g{i}"))).collect(),
        };
        let s = select_ec_scheme(&pool, EcTargets { k_target: 4, n_max: 7 });
        assert_eq!((s.k, s.n), (4, 7));
    }

    #[test]
    fn ec_selection_single_group_means_no_redundancy() {
        let pool = PoolSnapshot {
            providers: vec![entry("solo"), entry("solo")],
        };
        let s = select_ec_scheme(&pool, EcTargets::default());
        assert_eq!((s.k, s.n), (1, 1));
    }

    #[test]
    fn enrich_populates_host_profile() {
        // Step 2: snapshot starts with None for host-side fields; enrich
        // closure fills them.
        let pool_provider = entry("a");
        let pid = pool_provider.provider_id;
        let mut snap = PoolSnapshot {
            providers: vec![pool_provider],
        };
        assert_eq!(snap.providers[0].max_object_bytes, None);
        snap.enrich(|qid| {
            assert_eq!(qid, pid);
            HostProfile {
                max_object_bytes: Some(200 * 1024 * 1024),
                cas_tier: Some(CasTier::EventualOnly),
                update_capability: UpdateCapability::None,
            }
        });
        assert_eq!(
            snap.providers[0].max_object_bytes,
            Some(200 * 1024 * 1024)
        );
        assert_eq!(snap.providers[0].cas_tier, Some(CasTier::EventualOnly));
    }

    #[test]
    fn eligibility_filter_drops_oversize_caps() {
        // Step 2 / Layer R1 baseline (ROUTING.md §13 Step 4): a 2 MiB
        // chunk skips the 64 KiB-cap provider and lands on the 200 MiB
        // and 128 MiB ones.
        let small = entry_with_cap("paste-rs", 64 * 1024);
        let medium = entry_with_cap("uguu", 128 * 1024 * 1024);
        let large = entry_with_cap("catbox", 200 * 1024 * 1024);
        let pool = PoolSnapshot {
            providers: vec![small.clone(), medium.clone(), large.clone()],
        };
        let scheme = ECScheme::new(1, 2).unwrap();
        let req = PlacementRequest::for_chunk(
            ChunkHash::from_bytes([2u8; 32]),
            2 * 1024 * 1024,
            scheme,
        );
        let filtered = eligibility_filter(&req, &pool);
        let groups: std::collections::HashSet<_> = filtered
            .providers
            .iter()
            .map(|p| p.trust_group.clone())
            .collect();
        assert!(!groups.contains(&small.trust_group));
        assert!(groups.contains(&medium.trust_group));
        assert!(groups.contains(&large.trust_group));
    }

    #[test]
    fn eligibility_filter_unknown_cap_passes_through() {
        // None means "plugin didn't declare"; we don't penalize it at
        // Stage 1 — surface the error from the plugin's put() call
        // instead. Step 4 may tighten this for known-untrusted plugins.
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b")],
        };
        let scheme = ECScheme::new(1, 2).unwrap();
        let req = PlacementRequest::for_chunk(
            ChunkHash::from_bytes([0u8; 32]),
            10 * 1024 * 1024 * 1024, // 10 GiB
            scheme,
        );
        let filtered = eligibility_filter(&req, &pool);
        assert_eq!(filtered.providers.len(), 2);
    }

    #[test]
    fn errors_when_too_few_groups() {
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("a")],
        };
        let scheme = ECScheme::new(2, 3).unwrap();
        let req = PlacementRequest::for_chunk(ChunkHash::from_bytes([0u8; 32]), 1024, scheme);
        let res = pick_shards_for_chunk(&req, &pool, DiversityPolicy::default());
        assert!(matches!(res, Err(PlacementError::InsufficientGroups { .. })));
    }
}
