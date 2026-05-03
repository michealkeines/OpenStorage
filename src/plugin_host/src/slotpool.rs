//! `slotpool` — engine-side tracker for reusable storage slots on
//! Update-capable backends.
//!
//! See ROUTING.md §5 for the full design rationale. Quick summary:
//!
//! Many free backends create a fresh handle for every put (`catbox`,
//! `uguu`, …). A few support **overwrite** (S3, GitHub, R2, Discord
//! webhook edit within 15 min). On the latter, the engine should *reuse*
//! the same handle on subsequent writes instead of orphaning the prior
//! handle and inflating the shadow registry. Slot pooling is the
//! subsystem that makes that reuse explicit.
//!
//! This module is the **substrate** (data model + API + concurrency).
//! The vfs/GC integration that drives slots from real put/delete flows
//! is Step 7b in ROUTING.md §13. Persistence is also Step 7b — today the
//! pool is in-memory and slots are forgotten on restart.
//!
//! Thread-safety: the `SlotPool` is shared via `Arc` and serialized by a
//! `Mutex`. Slot ops are O(log n) on the slot count; pool sizes are
//! expected in the tens-to-thousands range, so this is fine.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use os_entities::NativeHandle;
use os_types::{ProviderId, UpdateCapability};

/// Engine-assigned opaque slot identifier. Local to a single SlotPool;
/// not stable across processes (Step 7b adds persistence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotId(pub u64);

/// Power-of-two byte ceiling. Buckets writes into size classes so a
/// 12 KiB chunk doesn't claim a 64 MiB slot and waste storage.
///
/// Constructed via [`SizeClass::ceiling`], which rounds up to the next
/// power of two with a 4 KiB minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SizeClass(u64);

impl SizeClass {
    pub const MIN: u64 = 4 * 1024;

    pub fn ceiling(bytes: u64) -> Self {
        let mut k = Self::MIN;
        while k < bytes {
            // saturating to handle pathological u64::MAX inputs
            k = k.saturating_mul(2);
            if k == 0 {
                k = u64::MAX;
                break;
            }
        }
        Self(k)
    }

    pub fn bytes(self) -> u64 {
        self.0
    }

    /// Does this slot's class hold a chunk of the given size?
    pub fn fits(self, chunk_bytes: u64) -> bool {
        self.0 >= chunk_bytes
    }
}

/// Lifecycle state. See ROUTING.md §5.3 for the full state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Newly allocated, no bytes yet.
    Empty,
    /// Write in flight. Don't lend to another owner.
    Pending,
    /// Holds an owner's bytes.
    Filled,
    /// Bytes have been overwritten but the owner that wrote them isn't
    /// finalized yet (e.g., crypto-erasure in progress; reserved for
    /// Step 8).
    Dirty,
    /// Owner released the slot. Up for grabs by the next compatible
    /// write.
    Forgotten,
}

/// Engine-side identifier for whoever currently rents a slot. For
/// chunk shards: the `chunk_hash` bytes XOR shard_index (caller's
/// choice). For named blobs (snapshot pointer, lease): a stable hash
/// of the logical name.
pub type SlotOwnerId = [u8; 32];

#[derive(Debug, Clone)]
pub struct Slot {
    pub slot_id: SlotId,
    pub provider_id: ProviderId,
    pub update_capability: UpdateCapability,
    pub size_class: SizeClass,
    pub state: SlotState,
    pub current_handle: Option<NativeHandle>,
    pub current_size: u64,
    pub owner: Option<SlotOwnerId>,
    pub reuse_count: u32,
}

#[derive(Default)]
pub struct SlotPool {
    inner: Mutex<SlotPoolInner>,
}

#[derive(Default)]
struct SlotPoolInner {
    slots: BTreeMap<SlotId, Slot>,
    next_id: u64,
    /// Reverse index: owner → currently bound slot.
    by_owner: BTreeMap<SlotOwnerId, SlotId>,
    /// Reverse index: (provider, handle bytes) → slot. Lets the delete
    /// path find a slot from the persisted Shard's provider+handle pair
    /// without storing slot_id in the Shard record.
    by_handle: BTreeMap<(ProviderId, Vec<u8>), SlotId>,
}

impl SlotPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh slot. Caller invokes `mark_filled` after the
    /// plugin's first put returns successfully.
    pub fn allocate(
        &self,
        provider: ProviderId,
        update: UpdateCapability,
        size_class: SizeClass,
    ) -> SlotId {
        let mut g = self.inner.lock().expect("slot pool mutex");
        g.next_id = g.next_id.saturating_add(1);
        let slot_id = SlotId(g.next_id);
        g.slots.insert(
            slot_id,
            Slot {
                slot_id,
                provider_id: provider,
                update_capability: update,
                size_class,
                state: SlotState::Pending,
                current_handle: None,
                current_size: 0,
                owner: None,
                reuse_count: 0,
            },
        );
        slot_id
    }

    /// Record a successful write. The slot transitions to `Filled` and
    /// the owner is indexed for `lookup_owner`. Both reverse indices
    /// (owner and handle) are populated so the delete path can find
    /// the slot from the persisted Shard record.
    pub fn mark_filled(
        &self,
        slot_id: SlotId,
        owner: SlotOwnerId,
        handle: NativeHandle,
        size: u64,
    ) {
        let mut g = self.inner.lock().expect("slot pool mutex");
        let (provider_id, prior_handle_bytes) = if let Some(s) = g.slots.get_mut(&slot_id) {
            // If we're marking a slot that already had a handle (rebind
            // case), drop the old by_handle entry so it doesn't dangle.
            let prior = s.current_handle.as_ref().map(|h| h.0.clone());
            s.state = SlotState::Filled;
            s.owner = Some(owner);
            s.current_handle = Some(handle.clone());
            s.current_size = size;
            s.reuse_count = s.reuse_count.saturating_add(1);
            (s.provider_id, prior)
        } else {
            return;
        };
        if let Some(p) = prior_handle_bytes {
            if p != handle.0 {
                g.by_handle.remove(&(provider_id, p));
            }
        }
        g.by_owner.insert(owner, slot_id);
        g.by_handle.insert((provider_id, handle.0), slot_id);
    }

    /// Find the slot owning a given (provider, handle) pair. Used by
    /// the delete path to release the slot without persisting `slot_id`
    /// in the Shard record.
    pub fn slot_for_handle(
        &self,
        provider: ProviderId,
        handle: &NativeHandle,
    ) -> Option<SlotId> {
        let g = self.inner.lock().expect("slot pool mutex");
        g.by_handle.get(&(provider, handle.0.clone())).copied()
    }

    /// Convenience: release the slot owning `(provider, handle)` if any.
    /// Returns `true` if a slot was released. The Shard delete path
    /// calls this for each persisted shard so the slot's bytes become
    /// available to a future writer (after Step 8's crypto-erase
    /// overwrite).
    pub fn release_by_handle(&self, provider: ProviderId, handle: &NativeHandle) -> bool {
        if let Some(slot_id) = self.slot_for_handle(provider, handle) {
            self.release(slot_id);
            true
        } else {
            false
        }
    }

    /// **Same-owner rebind** (ROUTING.md §5.4 case 1). Looks up the
    /// owner and returns its current slot if any. Caller compares
    /// `slot.size_class.fits(chunk_bytes)` and
    /// `slot.update_capability.allows_reuse()` before deciding to call
    /// `update()` on the plugin.
    pub fn lookup_owner(&self, owner: &SlotOwnerId) -> Option<Slot> {
        let g = self.inner.lock().expect("slot pool mutex");
        let slot_id = g.by_owner.get(owner)?;
        g.slots.get(slot_id).cloned()
    }

    /// **Forgotten-slot rental** (ROUTING.md §5.4 case 2). Returns the
    /// first Forgotten slot on the given provider whose size class
    /// fits the chunk and whose update capability allows reuse.
    /// Deterministic by SlotId order so tests are reproducible.
    pub fn find_forgotten(
        &self,
        provider: ProviderId,
        chunk_bytes: u64,
    ) -> Option<Slot> {
        let g = self.inner.lock().expect("slot pool mutex");
        g.slots
            .values()
            .find(|s| {
                s.state == SlotState::Forgotten
                    && s.provider_id == provider
                    && s.size_class.fits(chunk_bytes)
                    && s.update_capability.allows_reuse()
            })
            .cloned()
    }

    /// Mark the slot as released by its current owner. The slot
    /// transitions to `Forgotten` and the owner index is dropped.
    /// `current_handle` is preserved so a future rebind can hand it to
    /// `plugin.update()`.
    /// Mark slot as released by its current owner. The slot transitions
    /// to `Forgotten`; `current_handle` is preserved so a future
    /// `rebind` can hand it to `plugin.update()`. The owner reverse
    /// index is dropped (the handle reverse index is preserved — the
    /// slot is still findable by (provider, handle) until a rebind
    /// replaces the handle).
    pub fn release(&self, slot_id: SlotId) {
        let mut g = self.inner.lock().expect("slot pool mutex");
        let dropped_owner = g.slots.get_mut(&slot_id).and_then(|s| {
            let prev = s.owner.take();
            s.state = SlotState::Forgotten;
            prev
        });
        if let Some(owner) = dropped_owner {
            g.by_owner.remove(&owner);
        }
    }

    /// Hand a `Forgotten` or `Empty` slot to a new owner. Returns the
    /// prior handle the caller passes to `plugin.update()`. `None` if
    /// the slot isn't reusable (wrong state or `UpdateCapability::None`).
    /// Both states are reusable: `Forgotten` still holds the prior
    /// owner's ciphertext at rest; `Empty` has been crypto-erased and
    /// holds random bytes. The plugin's `update` overwrites in either
    /// case.
    pub fn rebind(
        &self,
        slot_id: SlotId,
        new_owner: SlotOwnerId,
    ) -> Option<NativeHandle> {
        let mut g = self.inner.lock().expect("slot pool mutex");
        let s = g.slots.get_mut(&slot_id)?;
        let reusable = matches!(s.state, SlotState::Forgotten | SlotState::Empty);
        if !reusable || !s.update_capability.allows_reuse() {
            return None;
        }
        s.state = SlotState::Pending;
        s.owner = Some(new_owner);
        s.reuse_count = s.reuse_count.saturating_add(1);
        let h = s.current_handle.clone();
        g.by_owner.insert(new_owner, slot_id);
        h
    }

    /// Slots awaiting crypto-erasure: `Forgotten` state on a backend
    /// that supports `TrueUpdate` and still holds a `current_handle`.
    /// The eraser walks this list, calls `plugin.update(handle, random)`
    /// to scrub the bytes, then transitions each slot to `Empty` via
    /// `mark_erased`.
    ///
    /// `AtomicReplace` providers are deliberately excluded: a
    /// pseudo-erase there would issue a *new* handle (creating a fresh
    /// orphan), defeating the whole point. ROUTING.md §5.5.
    pub fn pending_erasure(&self) -> Vec<Slot> {
        let g = self.inner.lock().expect("slot pool mutex");
        g.slots
            .values()
            .filter(|s| {
                s.state == SlotState::Forgotten
                    && matches!(s.update_capability, UpdateCapability::TrueUpdate)
                    && s.current_handle.is_some()
            })
            .cloned()
            .collect()
    }

    /// Transition `Forgotten → Empty` after the bytes-at-rest have been
    /// overwritten with random noise (caller's responsibility — the
    /// engine's `erase_pending_slots` is the canonical caller).
    /// `current_handle` is preserved so a future `rebind` can hand it
    /// to `plugin.update()`.
    pub fn mark_erased(&self, slot_id: SlotId) {
        let mut g = self.inner.lock().expect("slot pool mutex");
        if let Some(s) = g.slots.get_mut(&slot_id) {
            if s.state == SlotState::Forgotten {
                s.state = SlotState::Empty;
            }
        }
    }

    /// Inspect a slot. Returns a clone, no lock held by caller.
    pub fn get(&self, slot_id: SlotId) -> Option<Slot> {
        let g = self.inner.lock().expect("slot pool mutex");
        g.slots.get(&slot_id).cloned()
    }

    /// How many slots currently exist (any state). Used by metrics + tests.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("slot pool mutex").slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_handle(tag: u8) -> NativeHandle {
        NativeHandle(vec![tag; 8])
    }

    #[test]
    fn size_class_rounds_up_to_power_of_two_min_4kib() {
        assert_eq!(SizeClass::ceiling(0).bytes(), 4 * 1024);
        assert_eq!(SizeClass::ceiling(1).bytes(), 4 * 1024);
        assert_eq!(SizeClass::ceiling(4 * 1024).bytes(), 4 * 1024);
        assert_eq!(SizeClass::ceiling(4 * 1024 + 1).bytes(), 8 * 1024);
        assert_eq!(SizeClass::ceiling(1_048_576).bytes(), 1_048_576);
        assert_eq!(SizeClass::ceiling(1_048_577).bytes(), 2 * 1_048_576);
    }

    #[test]
    fn size_class_fits_predicate() {
        let cls = SizeClass::ceiling(1_048_576); // 1 MiB
        assert!(cls.fits(1));
        assert!(cls.fits(1_000_000));
        assert!(cls.fits(1_048_576));
        assert!(!cls.fits(1_048_577));
    }

    #[test]
    fn allocate_yields_pending_slot_with_no_owner() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        let s = pool.get(id).unwrap();
        assert_eq!(s.state, SlotState::Pending);
        assert!(s.owner.is_none());
        assert!(s.current_handle.is_none());
    }

    /// Layer R4 (data-model level — ROUTING.md §12 R4): same-owner
    /// rebind. After mark_filled, lookup_owner returns the same slot
    /// with the original handle. The end-to-end CLI version of this
    /// baseline is Step 7b's responsibility.
    #[test]
    fn r4_same_owner_lookup_returns_filled_slot_and_handle() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let class = SizeClass::ceiling(1024);
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, class);

        let owner: SlotOwnerId = [42u8; 32];
        let h = dummy_handle(0xAB);
        pool.mark_filled(id, owner, h.clone(), 800);

        let found = pool.lookup_owner(&owner).expect("owner indexed");
        assert_eq!(found.slot_id, id);
        assert_eq!(found.state, SlotState::Filled);
        assert_eq!(found.current_handle.as_ref(), Some(&h));
        assert_eq!(found.owner, Some(owner));
    }

    #[test]
    fn release_marks_forgotten_and_clears_owner_index() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        let owner: SlotOwnerId = [9u8; 32];
        pool.mark_filled(id, owner, dummy_handle(0xCD), 100);
        pool.release(id);

        let s = pool.get(id).unwrap();
        assert_eq!(s.state, SlotState::Forgotten);
        assert!(s.owner.is_none());
        // The handle is preserved so a future rebind can hand it to
        // `plugin.update()`.
        assert!(s.current_handle.is_some());
        assert!(pool.lookup_owner(&owner).is_none());
    }

    /// Layer R5 (data-model level — ROUTING.md §12 R5): after a slot is
    /// released, find_forgotten + rebind hand the slot to a new owner
    /// and return the prior handle for plugin.update.
    #[test]
    fn r5_find_forgotten_then_rebind_hands_handle_to_new_owner() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let class = SizeClass::ceiling(2 * 1024 * 1024);

        // Owner A writes, then releases.
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, class);
        let owner_a: SlotOwnerId = [1u8; 32];
        let h = dummy_handle(0x11);
        pool.mark_filled(id, owner_a, h.clone(), 1_500_000);
        pool.release(id);

        // Owner B (different chunk, same size class) finds and rebinds.
        let owner_b: SlotOwnerId = [2u8; 32];
        let candidate = pool.find_forgotten(pid, 1_500_000).expect("forgotten match");
        assert_eq!(candidate.slot_id, id);
        let prior_handle = pool.rebind(candidate.slot_id, owner_b).expect("rebind");
        assert_eq!(prior_handle, h);

        let s = pool.get(id).unwrap();
        assert_eq!(s.state, SlotState::Pending);
        assert_eq!(s.owner, Some(owner_b));
        assert_eq!(s.reuse_count, 2); // mark_filled + rebind
    }

    #[test]
    fn find_forgotten_skips_wrong_provider() {
        let pool = SlotPool::new();
        let p1 = ProviderId::new_v7();
        let p2 = ProviderId::new_v7();
        let id = pool.allocate(p1, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(id, [3u8; 32], dummy_handle(0xEE), 100);
        pool.release(id);
        // Different provider → no match.
        assert!(pool.find_forgotten(p2, 100).is_none());
        // Right provider → match.
        assert!(pool.find_forgotten(p1, 100).is_some());
    }

    #[test]
    fn find_forgotten_skips_too_small_slots() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let small =
            pool.allocate(pid, UpdateCapability::TrueUpdate, SizeClass::ceiling(4 * 1024));
        pool.mark_filled(small, [4u8; 32], dummy_handle(0xAA), 1024);
        pool.release(small);
        // A 100 KiB chunk doesn't fit the 4 KiB slot.
        assert!(pool.find_forgotten(pid, 100 * 1024).is_none());
    }

    #[test]
    fn find_forgotten_skips_non_update_capable_providers() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::None, SizeClass::ceiling(1024));
        pool.mark_filled(id, [5u8; 32], dummy_handle(0xBB), 100);
        pool.release(id);
        assert!(pool.find_forgotten(pid, 100).is_none());
    }

    #[test]
    fn pending_erasure_lists_truu_update_forgotten_only() {
        let pool = SlotPool::new();
        let p = ProviderId::new_v7();
        // A: TrueUpdate + Filled → not pending
        let a = pool.allocate(p, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(a, [0u8; 32], dummy_handle(0xA1), 100);
        // B: TrueUpdate + Forgotten → pending
        let b = pool.allocate(p, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(b, [1u8; 32], dummy_handle(0xB1), 100);
        pool.release(b);
        // C: AtomicReplace + Forgotten → NOT pending (would create an orphan).
        let c = pool.allocate(p, UpdateCapability::AtomicReplace, SizeClass::ceiling(1024));
        pool.mark_filled(c, [2u8; 32], dummy_handle(0xC1), 100);
        pool.release(c);

        let pending = pool.pending_erasure();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].slot_id, b);
    }

    #[test]
    fn mark_erased_transitions_forgotten_to_empty_only() {
        let pool = SlotPool::new();
        let p = ProviderId::new_v7();
        let id = pool.allocate(p, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(id, [0u8; 32], dummy_handle(0xEE), 100);
        // From Filled: no-op.
        pool.mark_erased(id);
        assert_eq!(pool.get(id).unwrap().state, SlotState::Filled);
        pool.release(id);
        pool.mark_erased(id);
        assert_eq!(pool.get(id).unwrap().state, SlotState::Empty);
    }

    #[test]
    fn rebind_accepts_empty_slot() {
        let pool = SlotPool::new();
        let p = ProviderId::new_v7();
        let id = pool.allocate(p, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(id, [0u8; 32], dummy_handle(0xEE), 100);
        pool.release(id);
        pool.mark_erased(id);
        // Empty slot is reusable.
        let h = pool.rebind(id, [9u8; 32]);
        assert!(h.is_some());
        assert_eq!(pool.get(id).unwrap().state, SlotState::Pending);
    }

    #[test]
    fn rebind_refuses_filled_slots() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        pool.mark_filled(id, [6u8; 32], dummy_handle(0xDD), 100);
        // Slot is Filled, not Forgotten. Rebind must refuse to avoid
        // stealing another owner's handle.
        assert!(pool.rebind(id, [7u8; 32]).is_none());
    }

    #[test]
    fn slot_for_handle_round_trips() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::TrueUpdate, SizeClass::ceiling(1024));
        let owner: SlotOwnerId = [11u8; 32];
        let h = dummy_handle(0x77);
        pool.mark_filled(id, owner, h.clone(), 100);
        assert_eq!(pool.slot_for_handle(pid, &h), Some(id));
        assert!(pool.release_by_handle(pid, &h));
        // After release, the handle index still points to the same slot
        // (it's now Forgotten).
        assert_eq!(pool.slot_for_handle(pid, &h), Some(id));
        let s = pool.get(id).unwrap();
        assert_eq!(s.state, SlotState::Forgotten);
    }

    #[test]
    fn rebind_refuses_non_update_capable_providers() {
        let pool = SlotPool::new();
        let pid = ProviderId::new_v7();
        let id = pool.allocate(pid, UpdateCapability::None, SizeClass::ceiling(1024));
        pool.mark_filled(id, [8u8; 32], dummy_handle(0xCC), 100);
        pool.release(id);
        // Even though the slot is now Forgotten, rebind must refuse
        // because update isn't supported.
        assert!(pool.rebind(id, [9u8; 32]).is_none());
    }

    /// The default `PluginContract::update` method returns NotSupported.
    /// Plugins that haven't opted in stay safe — the slot pool sees the
    /// error and falls back to a fresh `put`. This test pins that
    /// default in place so a future trait edit doesn't silently change
    /// it.
    #[tokio::test]
    async fn plugin_contract_update_default_is_not_supported() {
        use crate::contract::{
            DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
        };
        use async_trait::async_trait;
        use os_entities::{NativeHandle, PutHint};
        use os_types::{
            CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile, QuotaReclaimed,
            QuotaState, Range, RateLimitState, Timestamp,
        };

        struct Stub;
        #[async_trait]
        impl PluginContract for Stub {
            async fn put(
                &self,
                _: &[u8],
                _: &PutHint,
            ) -> crate::Result<PutResult> {
                unreachable!()
            }
            async fn get(
                &self,
                _: &NativeHandle,
                _: Option<Range>,
            ) -> crate::Result<Vec<u8>> {
                unreachable!()
            }
            async fn peek(&self, _: &NativeHandle) -> crate::Result<PeekResult> {
                unreachable!()
            }
            async fn delete(&self, _: &NativeHandle) -> crate::Result<DeleteResult> {
                Ok(DeleteResult {
                    outcome: DeleteOutcome::NotSupported,
                    quota_reclaimed: QuotaReclaimed::No,
                    cached_elsewhere_risk: CachedElsewhereRisk::Low,
                    tombstone_clears_at: None,
                })
            }
            async fn health(&self) -> crate::Result<HealthReport> {
                Ok(HealthReport {
                    state: HealthState::Healthy,
                    quota: QuotaState {
                        total: None,
                        used: None,
                        untrusted: true,
                    },
                    rate_limit: RateLimitState {
                        remaining: u32::MAX,
                        reset_at: Timestamp::from_string("n/a"),
                    },
                    latency: LatencyProfile::default(),
                    score: HealthScore::new(1.0),
                })
            }
        }

        let s = Stub;
        let r = s.update(&NativeHandle(vec![0]), b"x").await;
        assert!(matches!(r, Err(crate::PluginError::NotSupported(_))));
    }
}
