//! Capacity and health value types.

use serde::{Deserialize, Serialize};

use super::time::Timestamp;

/// Reed–Solomon `(k, n)` scheme. Invariants: `1 ≤ k ≤ n`, `n ≤ 32`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
pub struct ECScheme {
    pub k: u8,
    pub n: u8,
}

impl ECScheme {
    pub fn new(k: u8, n: u8) -> Result<Self, &'static str> {
        if k == 0 || k > n {
            return Err("invalid (k, n): need 1 ≤ k ≤ n");
        }
        if n > 32 {
            return Err("n must not exceed 32");
        }
        Ok(Self { k, n })
    }
    /// Plain replication = `(1, n)`.
    pub fn replication(n: u8) -> Self {
        Self { k: 1, n }
    }
    pub fn parity(&self) -> u8 {
        self.n - self.k
    }
}

/// Pure replication factor. Used when the redundancy mode is `replication`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ReplicationFactor(pub u8);

/// Health score in `[0.0, 1.0]`. Constructor clamps; deserialization accepts
/// any float and clamps on read.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HealthScore(f32);

impl HealthScore {
    pub const MIN: Self = Self(0.0);
    pub const MAX: Self = Self(1.0);

    pub fn new(v: f32) -> Self {
        if v.is_nan() {
            return Self(0.0);
        }
        Self(v.clamp(0.0, 1.0))
    }
    pub fn value(self) -> f32 {
        self.0
    }
}

impl Default for HealthScore {
    fn default() -> Self {
        Self::MAX
    }
}

impl Eq for HealthScore {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for HealthScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuotaState {
    pub total: Option<u64>,
    pub used: Option<u64>,
    pub untrusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateLimitState {
    pub remaining: u32,
    pub reset_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct LatencyProfile {
    pub p50_ms: u32,
    pub p95_ms: u32,
    pub p99_ms: u32,
}

/// Engine-side classification of a plugin error. Distinct from the plugin's
/// self-reported `HealthState` (which is in `os-plugin-host`). The engine
/// maintains *its* view of every provider based on observed errors over a
/// sliding window — this enum is the input to that classifier.
///
/// Layer 2 of `STRUCTURAL_REWORK.md` introduces this so a Discord ban
/// (auth failures across many objects) is distinguishable from a
/// transient network blip and from a one-off rate-limit hiccup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorClass {
    /// 401/403, account banned, token revoked. Repeated → quarantine fast.
    #[serde(rename = "auth")]
    Auth,
    /// 429 with Retry-After. Backs off; should clear.
    #[serde(rename = "rate_limit")]
    RateLimit,
    /// Connection reset, timeout, DNS. Transient infra.
    #[serde(rename = "network")]
    Network,
    /// 404 — handle isn't there. Catalogued separately because read-repair
    /// reacts to it differently from auth/network.
    #[serde(rename = "not_found")]
    NotFound,
    /// AEAD verify fail / hash mismatch — backend silently lost or
    /// tampered with the bytes. Drives F-HM-2 read-repair.
    #[serde(rename = "corruption")]
    Corruption,
    /// Anything else; doesn't move the classifier on its own.
    #[serde(rename = "other")]
    Other,
}

/// Engine-maintained provider lifecycle, distinct from the plugin's
/// self-reported `HealthState`. Placement consults this; repair reacts
/// when a transition lands.
///
/// State machine:
///
/// ```text
///                        ┌── 5+ Auth in 60s ──┐
///   Active ──── error ──►│                    │
///      ▲                 ▼                    │
///      │           Quarantined ──── 5+ min idle ──► Active
///      │                 │
///      │          long-quarantined or repeated bans
///      │                 │
///      │                 ▼
///      └──── (manual clear) ──── Banned
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderHealth {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "quarantined")]
    Quarantined { reason: ErrorClass, since: Timestamp },
    #[serde(rename = "banned")]
    Banned { since: Timestamp },
}

impl ProviderHealth {
    pub fn is_active(&self) -> bool {
        matches!(self, ProviderHealth::Active)
    }
    pub fn is_banned(&self) -> bool {
        matches!(self, ProviderHealth::Banned { .. })
    }
}

impl Default for ProviderHealth {
    fn default() -> Self {
        ProviderHealth::Active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tier {
    #[serde(rename = "hot")]
    Hot,
    #[serde(rename = "warm")]
    Warm,
    #[serde(rename = "cold")]
    Cold,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_scheme_validates() {
        assert!(ECScheme::new(0, 4).is_err());
        assert!(ECScheme::new(5, 4).is_err());
        assert!(ECScheme::new(33, 33).is_err());
        assert_eq!(ECScheme::new(2, 4).unwrap().parity(), 2);
    }

    #[test]
    fn health_score_clamps() {
        assert_eq!(HealthScore::new(2.0).value(), 1.0);
        assert_eq!(HealthScore::new(-1.0).value(), 0.0);
        assert_eq!(HealthScore::new(f32::NAN).value(), 0.0);
    }
}
