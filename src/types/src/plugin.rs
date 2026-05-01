//! Plugin-interaction value types.
//!
//! See `PLUGIN_SDK.md` §6 for the canonical definition of `Capability`. This
//! module mirrors that closed set as a typed enum.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "put")]
    Put,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "peek")]
    Peek,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "list")]
    List,
    #[serde(rename = "range_read")]
    RangeRead,
    #[serde(rename = "atomic_replace")]
    AtomicReplace,
    #[serde(rename = "cas_write")]
    CasWrite,
    #[serde(rename = "signed_fetch")]
    SignedFetch,
    #[serde(rename = "tombstone")]
    Tombstone,
    #[serde(rename = "quota_report")]
    QuotaReport,
}

/// Full capability declaration for a plugin instance.
///
/// `flags` are the closed-set capabilities. `scalar` carries vendor-defined
/// scalar values (e.g., `max_object_bytes`). The plugin's manifest enumerates
/// both; the engine treats unknown scalar keys as opaque metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub flags: BTreeSet<Capability>,
    pub scalar: std::collections::BTreeMap<String, i64>,
}

impl CapabilitySet {
    pub fn has(&self, c: Capability) -> bool {
        self.flags.contains(&c)
    }
    pub fn with(mut self, c: Capability) -> Self {
        self.flags.insert(c);
        self
    }
}

/// Returned by `put` when `replaces_handle` was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PriorHandleState {
    #[serde(rename = "overwritten")]
    Overwritten,
    #[serde(rename = "removed")]
    Removed,
    #[serde(rename = "tombstoned")]
    Tombstoned,
    #[serde(rename = "abandoned")]
    Abandoned,
    #[serde(rename = "unknown")]
    Unknown,
}

/// Returned by `delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeleteOutcome {
    #[serde(rename = "removed")]
    Removed,
    #[serde(rename = "tombstoned")]
    Tombstoned,
    #[serde(rename = "abandoned")]
    Abandoned,
    #[serde(rename = "not_supported")]
    NotSupported,
    #[serde(rename = "not_found")]
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuotaReclaimed {
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "no")]
    No,
    #[serde(rename = "unknown")]
    Unknown,
}

/// Half-open byte range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

impl Range {
    pub fn new(start: u64, end: u64) -> Result<Self, &'static str> {
        if end < start {
            return Err("range: end must be ≥ start");
        }
        Ok(Self { start, end })
    }
    pub fn len(&self) -> u64 {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_set_has() {
        let cs = CapabilitySet::default()
            .with(Capability::Put)
            .with(Capability::Get);
        assert!(cs.has(Capability::Put));
        assert!(!cs.has(Capability::Delete));
    }

    #[test]
    fn range_validates() {
        assert!(Range::new(5, 4).is_err());
        let r = Range::new(2, 7).unwrap();
        assert_eq!(r.len(), 5);
    }
}
