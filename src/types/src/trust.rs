//! Trust and legal value types.

use serde::{Deserialize, Serialize};

/// Backend operator that owns a plugin's bytes. Used to enforce the diversity
/// rule when picking shards (no two shards under the same correlation group).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustCorrelationGroup(pub String);

impl TrustCorrelationGroup {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Plugin's declared posture against the backend's terms of service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LegalClass {
    #[serde(rename = "green")]
    Green,
    #[serde(rename = "yellow")]
    Yellow,
    #[serde(rename = "red")]
    Red,
}

/// Backend-reported risk that ciphertext bytes survive in third-party caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CachedElsewhereRisk {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

/// Plugin-declared retention promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurabilityClass {
    #[serde(rename = "ephemeral")]
    Ephemeral,
    #[serde(rename = "weekly")]
    Weekly,
    #[serde(rename = "yearly")]
    Yearly,
    #[serde(rename = "archival")]
    Archival,
}
