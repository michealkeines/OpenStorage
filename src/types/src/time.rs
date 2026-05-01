//! Time and causality value types.
//!
//! `Hlc` (Hybrid Logical Clock) is the durable causality primitive: every WAL
//! entry carries one, and CRDT merges use it for tiebreaking. Comparison is by
//! `(physical, logical)`; the caller must apply the device-id tiebreak when an
//! HLC pair is genuinely equal.
//!
//! `Timestamp` is wall-clock for human-facing fields only — never for ordering.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// Hybrid Logical Clock. `physical` is unix milliseconds; `logical` is a
/// monotonic counter that increments when two events share a physical reading.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize,
)]
pub struct Hlc {
    pub physical: u64,
    pub logical: u32,
}

impl Hlc {
    pub const ZERO: Self = Self {
        physical: 0,
        logical: 0,
    };

    pub fn new(physical: u64, logical: u32) -> Self {
        Self { physical, logical }
    }

    /// Local-event tick: produce a new HLC based on a fresh wall-clock reading
    /// and the previously-emitted HLC. Always strictly greater than `prev`.
    pub fn tick_local(prev: Self, now_ms: u64) -> Self {
        if now_ms > prev.physical {
            Self {
                physical: now_ms,
                logical: 0,
            }
        } else {
            Self {
                physical: prev.physical,
                logical: prev.logical + 1,
            }
        }
    }

    /// Merge a remote HLC with our local view; returns the new local view that
    /// is `> remote` and `> local`. Used when receiving a foreign WAL entry.
    pub fn merge_remote(local: Self, remote: Self, now_ms: u64) -> Self {
        let max_phys = local.physical.max(remote.physical).max(now_ms);
        let logical = if max_phys == local.physical && max_phys == remote.physical {
            local.logical.max(remote.logical) + 1
        } else if max_phys == local.physical {
            local.logical + 1
        } else if max_phys == remote.physical {
            remote.logical + 1
        } else {
            0
        };
        Self {
            physical: max_phys,
            logical,
        }
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.physical.cmp(&other.physical) {
            Ordering::Equal => self.logical.cmp(&other.logical),
            o => o,
        }
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.physical, self.logical)
    }
}

/// RFC 3339 timestamp with millisecond precision (UTC). Stored as a string for
/// stable serialization across the persistence boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub String);

impl Timestamp {
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Snapshot version counter. Never decreases; rollback detection refuses any
/// fetched pointer with a counter `<=` the cached one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MonotonicCounter(pub u64);

impl MonotonicCounter {
    pub const ZERO: Self = Self(0);
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// ISO 8601 duration form. Used for TTLs and intervals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Duration(pub String);

impl Duration {
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_total_order() {
        let a = Hlc::new(10, 0);
        let b = Hlc::new(10, 1);
        let c = Hlc::new(11, 0);
        assert!(a < b && b < c);
    }

    #[test]
    fn hlc_tick_local_advances_when_clock_moves() {
        let prev = Hlc::new(10, 0);
        assert_eq!(Hlc::tick_local(prev, 11), Hlc::new(11, 0));
    }

    #[test]
    fn hlc_tick_local_bumps_logical_when_clock_stalls() {
        let prev = Hlc::new(10, 0);
        assert_eq!(Hlc::tick_local(prev, 10), Hlc::new(10, 1));
        assert_eq!(Hlc::tick_local(prev, 9), Hlc::new(10, 1));
    }

    #[test]
    fn hlc_merge_dominates_inputs() {
        let l = Hlc::new(10, 5);
        let r = Hlc::new(12, 1);
        let m = Hlc::merge_remote(l, r, 11);
        assert!(m > l && m > r);
    }
}
