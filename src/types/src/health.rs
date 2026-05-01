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
