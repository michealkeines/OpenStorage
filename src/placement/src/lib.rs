//! os-placement — pure shard placement.
//!
//! Given a `PoolSnapshot` and a `(chunk_hash, shard_index)`, returns a
//! deterministic `ProviderId`. No I/O. The L4 caller fetches the pool from
//! `os-vault::current_pool()` and passes it in.

#![forbid(unsafe_code)]

use os_entities::Provider;
use os_types::{
    CapabilitySet, ChunkHash, ECScheme, HealthScore, ProviderId, Tier, TrustCorrelationGroup,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlacementError {
    #[error("placement impossible: pool has no providers with required capabilities")]
    Impossible,
    #[error("not enough distinct trust groups: have {have}, need {need}")]
    InsufficientGroups { have: usize, need: usize },
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
}

impl PoolSnapshot {
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
            })
            .collect();
        Self { providers: entries }
    }
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
pub fn pick_shards_for_chunk(
    chunk_hash: ChunkHash,
    scheme: ECScheme,
    pool: &PoolSnapshot,
    diversity: DiversityPolicy,
    tier: Tier,
) -> Result<Vec<(u8, ProviderId)>, PlacementError> {
    let _ = tier;
    let n = scheme.n as usize;
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
        let pick = best_pick(chunk_hash, shard_index, pool, &used_groups, &diversity)
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
        }
    }

    #[test]
    fn distinct_groups_assigned() {
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("b"), entry("c"), entry("d")],
        };
        let scheme = ECScheme::new(2, 3).unwrap();
        let picks = pick_shards_for_chunk(
            ChunkHash::from_bytes([1u8; 32]),
            scheme,
            &pool,
            DiversityPolicy::default(),
            Tier::Hot,
        )
        .unwrap();
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
        let h = ChunkHash::from_bytes([7u8; 32]);
        let a = pick_shards_for_chunk(h, scheme, &pool, DiversityPolicy::default(), Tier::Hot)
            .unwrap();
        let b = pick_shards_for_chunk(h, scheme, &pool, DiversityPolicy::default(), Tier::Hot)
            .unwrap();
        assert_eq!(a, b);
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
    fn errors_when_too_few_groups() {
        let pool = PoolSnapshot {
            providers: vec![entry("a"), entry("a")],
        };
        let scheme = ECScheme::new(2, 3).unwrap();
        let res = pick_shards_for_chunk(
            ChunkHash::from_bytes([0u8; 32]),
            scheme,
            &pool,
            DiversityPolicy::default(),
            Tier::Hot,
        );
        assert!(matches!(res, Err(PlacementError::InsufficientGroups { .. })));
    }
}
