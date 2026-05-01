//! CRDT field wrappers used in entity records.
//!
//! These are *fields*, not WAL ops. The WAL op vocabulary lives in
//! `os-wal::Op`; this module gives entity authors a typed view of what a
//! field's *current resolved value* looks like after merge.

use std::collections::BTreeMap;

use os_types::{DeviceId, Hlc};
use serde::{Deserialize, Serialize};

/// Last-Writer-Wins register. The single resolved value plus the HLC and
/// device that wrote it (for tiebreaking and audit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwRegister<T> {
    pub value: T,
    pub hlc: Hlc,
    pub device_id: DeviceId,
}

impl<T> LwwRegister<T> {
    pub fn new(value: T, hlc: Hlc, device_id: DeviceId) -> Self {
        Self {
            value,
            hlc,
            device_id,
        }
    }
}

impl<T: Clone> LwwRegister<T> {
    /// Pick the winner between two writes with HLC + device-id tiebreak.
    pub fn merge(self, other: Self) -> Self {
        if cmp_hlc_dev((self.hlc, self.device_id), (other.hlc, other.device_id))
            == std::cmp::Ordering::Less
        {
            other
        } else {
            self
        }
    }
}

/// LwwSet: same as LwwRegister but with a `previous_value` invariant tracked
/// for the Case-6 demotion rule (see DESIGN.md §10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwSet<T> {
    pub value: T,
    pub previous_value: Option<T>,
    pub hlc: Hlc,
    pub device_id: DeviceId,
}

impl<T> LwwSet<T> {
    pub fn new(value: T, previous_value: Option<T>, hlc: Hlc, device_id: DeviceId) -> Self {
        Self {
            value,
            previous_value,
            hlc,
            device_id,
        }
    }
}

/// Observed-remove set. `add_id` keys allow remove ops to cancel only adds
/// they have observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrSet<T> {
    /// add_id → value
    pub adds: BTreeMap<u128, T>,
    /// add_ids that have been removed
    pub tombstones: std::collections::BTreeSet<u128>,
}

impl<T> OrSet<T> {
    pub fn new() -> Self {
        Self {
            adds: BTreeMap::new(),
            tombstones: std::collections::BTreeSet::new(),
        }
    }
    pub fn add(&mut self, add_id: u128, value: T) {
        self.adds.insert(add_id, value);
    }
    pub fn remove(&mut self, observed_add_ids: impl IntoIterator<Item = u128>) {
        for id in observed_add_ids {
            self.tombstones.insert(id);
        }
    }
    pub fn live_values(&self) -> impl Iterator<Item = &T> {
        self.adds
            .iter()
            .filter(|(id, _)| !self.tombstones.contains(id))
            .map(|(_, v)| v)
    }
    pub fn is_member(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.live_values().any(|v| v == value)
    }
    pub fn len(&self) -> usize {
        self.adds.len() - self.tombstones.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for OrSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// PN-Counter (positive-negative). Each device has its own pos/neg buckets;
/// the resolved value is the sum across buckets.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Counter {
    pub buckets: BTreeMap<DeviceId, CounterBucket>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CounterBucket {
    pub pos: u64,
    pub neg: u64,
}

impl Counter {
    pub fn value(&self) -> i64 {
        let mut sum: i64 = 0;
        for b in self.buckets.values() {
            sum = sum.saturating_add(b.pos as i64).saturating_sub(b.neg as i64);
        }
        sum
    }
    pub fn inc(&mut self, device: DeviceId, delta: i64) {
        let b = self.buckets.entry(device).or_default();
        if delta >= 0 {
            b.pos = b.pos.saturating_add(delta as u64);
        } else {
            b.neg = b.neg.saturating_add(delta.unsigned_abs());
        }
    }
}

fn cmp_hlc_dev(a: (Hlc, DeviceId), b: (Hlc, DeviceId)) -> std::cmp::Ordering {
    match a.0.cmp(&b.0) {
        std::cmp::Ordering::Equal => a.1.0.as_bytes().cmp(b.1.0.as_bytes()),
        o => o,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceId {
        DeviceId::new_v7()
    }

    #[test]
    fn lww_register_merge_picks_higher_hlc() {
        let d = dev();
        let a = LwwRegister::new("a".to_string(), Hlc::new(1, 0), d);
        let b = LwwRegister::new("b".to_string(), Hlc::new(2, 0), d);
        assert_eq!(a.clone().merge(b.clone()).value, "b");
        assert_eq!(b.merge(a).value, "b");
    }

    #[test]
    fn or_set_observed_remove() {
        let mut s = OrSet::<u64>::new();
        s.add(1, 100);
        s.add(2, 100);
        s.remove([1]);
        assert_eq!(s.live_values().count(), 1);
    }

    #[test]
    fn counter_sums_across_buckets() {
        let mut c = Counter::default();
        let d1 = dev();
        let d2 = dev();
        c.inc(d1, 5);
        c.inc(d2, 3);
        c.inc(d1, -2);
        assert_eq!(c.value(), 6);
    }
}
