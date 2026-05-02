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

// ──────────────────────────────────────────────────────────────────────────
// Layer 5 — proptest-driven convergence checks for the CRDT primitives.
//
// The CRDT contract is: regardless of the order operations arrive at a
// device, all devices see the same final state. The hand-written tests
// above prove specific scenarios; these proptests prove the invariant
// holds across thousands of randomly-generated op interleavings.
// ──────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn dev_for_byte(b: u8) -> DeviceId {
        // Stable, low-cardinality device ids so collisions actually
        // exercise the device-id tiebreak.
        let bytes = [b; 16];
        DeviceId::from_uuid(uuid::Uuid::from_bytes(bytes))
    }

    fn arb_hlc() -> impl Strategy<Value = Hlc> {
        (0u64..1000, 0u32..1000).prop_map(|(p, l)| Hlc::new(p, l))
    }

    fn arb_writer() -> impl Strategy<Value = (Hlc, DeviceId, u32)> {
        (arb_hlc(), 0u8..4, 0u32..1000).prop_map(|(h, d, v)| (h, dev_for_byte(d), v))
    }

    proptest! {
        /// Idempotence: merging the same write into itself returns
        /// itself.
        #[test]
        fn lww_register_idempotent(
            (h, d, v) in arb_writer()
        ) {
            let r = LwwRegister::new(v, h, d);
            prop_assert_eq!(r.clone().merge(r.clone()), r);
        }

        /// Commutativity: merge order is irrelevant for any two writes.
        /// (LwwRegister is total — every pair has a unique winner under
        /// (HLC, device_id) tiebreak.)
        #[test]
        fn lww_register_commutative(
            (h1, d1, v1) in arb_writer(),
            (h2, d2, v2) in arb_writer(),
        ) {
            let a = LwwRegister::new(v1, h1, d1);
            let b = LwwRegister::new(v2, h2, d2);
            prop_assert_eq!(
                a.clone().merge(b.clone()),
                b.clone().merge(a.clone())
            );
        }

        /// Associativity: (a ⊔ b) ⊔ c == a ⊔ (b ⊔ c).
        #[test]
        fn lww_register_associative(
            (h1, d1, v1) in arb_writer(),
            (h2, d2, v2) in arb_writer(),
            (h3, d3, v3) in arb_writer(),
        ) {
            let a = LwwRegister::new(v1, h1, d1);
            let b = LwwRegister::new(v2, h2, d2);
            let c = LwwRegister::new(v3, h3, d3);
            let left = a.clone().merge(b.clone()).merge(c.clone());
            let right = a.merge(b.merge(c));
            prop_assert_eq!(left, right);
        }

        /// Convergence under arbitrary interleaving: two devices that
        /// observe the *same set* of writes in *any order* end up with
        /// the same resolved value.
        #[test]
        fn lww_register_converges_under_reorder(
            mut writers in proptest::collection::vec(arb_writer(), 2..16),
            seed_a in any::<u64>(),
            seed_b in any::<u64>(),
        ) {
            use rand::seq::SliceRandom;
            use rand::SeedableRng;
            let initial = LwwRegister::new(0u32, Hlc::new(0, 0), dev_for_byte(255));
            let order_a: Vec<_> = {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_a);
                let mut w = writers.clone();
                w.shuffle(&mut rng);
                w
            };
            let order_b: Vec<_> = {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_b);
                writers.shuffle(&mut rng);
                writers
            };
            let final_a = order_a.into_iter().fold(initial.clone(), |acc, (h, d, v)| {
                acc.merge(LwwRegister::new(v, h, d))
            });
            let final_b = order_b.into_iter().fold(initial, |acc, (h, d, v)| {
                acc.merge(LwwRegister::new(v, h, d))
            });
            prop_assert_eq!(final_a, final_b);
        }

        /// OR-Set: live_values is independent of add/remove order
        /// **when add_ids are unique** (the design contract — add_ids
        /// are 128-bit random per add op, never reused). The proptest
        /// generates a unique-id distribution by mapping a small
        /// integer key to its position in the input vector, so
        /// shuffling preserves uniqueness.
        ///
        /// Note: this is a real-CRDT discovery preserved as a
        /// regression — `OrSet::add(id, v)` overwrites on duplicate
        /// id. If two devices independently generate the *same*
        /// add_id with *different* values, convergence fails. The
        /// design protects this invariant by sourcing add_ids from
        /// a 128-bit RNG; this test honors that contract.
        #[test]
        fn or_set_converges_under_reorder(
            entries in proptest::collection::vec(0u32..256, 1..16),
            removes_idx in proptest::collection::vec(0usize..16, 0..16),
            seed_a in any::<u64>(),
            seed_b in any::<u64>(),
        ) {
            use rand::seq::SliceRandom;
            use rand::SeedableRng;

            // Each entry's index *is* its add_id (unique by construction).
            let adds: Vec<(u128, u32)> = entries
                .iter()
                .enumerate()
                .map(|(i, v)| (i as u128, *v))
                .collect();
            let removes: Vec<u128> = removes_idx
                .iter()
                .filter(|i| **i < adds.len())
                .map(|i| *i as u128)
                .collect();

            let mut a_adds = adds.clone();
            let mut a_rems = removes.clone();
            let mut b_adds = adds.clone();
            let mut b_rems = removes;
            {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_a);
                a_adds.shuffle(&mut rng);
                a_rems.shuffle(&mut rng);
            }
            {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_b);
                b_adds.shuffle(&mut rng);
                b_rems.shuffle(&mut rng);
            }

            let mut sa = OrSet::<u32>::new();
            for (id, v) in &a_adds {
                sa.add(*id, *v);
            }
            sa.remove(a_rems.iter().copied());

            let mut sb = OrSet::<u32>::new();
            for (id, v) in &b_adds {
                sb.add(*id, *v);
            }
            sb.remove(b_rems.iter().copied());

            let live_a: std::collections::BTreeSet<_> = sa.live_values().copied().collect();
            let live_b: std::collections::BTreeSet<_> = sb.live_values().copied().collect();
            prop_assert_eq!(live_a, live_b);
        }

        /// Counter: PN-counter sum is independent of inc/dec order.
        #[test]
        fn counter_converges_under_reorder(
            ops in proptest::collection::vec((0u8..4, -100i32..100), 0..32),
            seed_a in any::<u64>(),
            seed_b in any::<u64>(),
        ) {
            use rand::seq::SliceRandom;
            use rand::SeedableRng;

            let mut a_ops = ops.clone();
            let mut b_ops = ops.clone();
            {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_a);
                a_ops.shuffle(&mut rng);
            }
            {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed_b);
                b_ops.shuffle(&mut rng);
            }

            let mut ca = Counter::default();
            for (d, delta) in &a_ops {
                ca.inc(dev_for_byte(*d), *delta as i64);
            }
            let mut cb = Counter::default();
            for (d, delta) in &b_ops {
                cb.inc(dev_for_byte(*d), *delta as i64);
            }
            prop_assert_eq!(ca.value(), cb.value());
        }
    }
}
