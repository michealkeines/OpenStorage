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
