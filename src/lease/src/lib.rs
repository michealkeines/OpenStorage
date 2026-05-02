//! os-lease — advisory primary-writer lease.
//!
//! Real deployments back the lease record with a metadata-vault plugin's
//! `cas_write` capability. The in-process implementation here exposes the
//! same semantics through a shared `Arc<Mutex<Option<LeaseRecord>>>`
//! "registry" so multi-device flows (F-MD-4 lease steal) are exercisable
//! end-to-end inside a single test process.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::Mutex;

use os_entities::LeaseRecord;
use os_types::{DeviceId, Ed25519Sig, LeaseId, Timestamp};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("lease held by another device")]
    Held,
    #[error("lease lost (CAS failed on renew)")]
    Lost,
    #[error("not held")]
    NotHeld,
    #[error("lease still live")]
    StillLive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Free,
    Held,
}

pub type LeaseRegistry = Arc<Mutex<Option<LeaseRecord>>>;

/// Backing store for the lease record. Two `LeaseService` instances sharing
/// the same registry simulate two devices on the same metadata-vault.
pub fn new_registry() -> LeaseRegistry {
    Arc::new(Mutex::new(None))
}

pub struct LeaseService {
    registry: LeaseRegistry,
    /// Last `LeaseId` we wrote (or stole). Renew compares against the
    /// registry's current record to detect steal.
    local: Mutex<Option<LeaseId>>,
}

impl LeaseService {
    pub fn new() -> Self {
        Self::with_registry(new_registry())
    }

    pub fn with_registry(registry: LeaseRegistry) -> Self {
        Self {
            registry,
            local: Mutex::new(None),
        }
    }

    pub fn registry(&self) -> LeaseRegistry {
        self.registry.clone()
    }

    /// Force-install a lease record into the local registry without
    /// CAS semantics. Used by the vault-backed lease path in `os-api`
    /// to mirror the lease_id chosen during a successful cas_write so
    /// subsequent renew/release calls match. The previous record (if
    /// any) is silently overwritten.
    pub fn install_local(&self, record: LeaseRecord) {
        *self.local.lock().expect("lease local") = Some(record.lease_id);
        *self.registry.lock().expect("lease registry") = Some(record);
    }

    pub fn state(&self) -> LeaseState {
        if self.registry.lock().expect("lease registry").is_some() {
            LeaseState::Held
        } else {
            LeaseState::Free
        }
    }

    pub fn current(&self) -> Option<LeaseRecord> {
        self.registry.lock().expect("lease registry").clone()
    }

    /// F-MD-4 — acquire when the registry is empty. Returns `Held` if a
    /// live record exists (use `try_steal` for a stale one).
    pub fn acquire(
        &self,
        holder: DeviceId,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<LeaseRecord, LeaseError> {
        let mut g = self.registry.lock().expect("lease registry");
        if g.is_some() {
            return Err(LeaseError::Held);
        }
        let record = LeaseRecord {
            lease_id: LeaseId::new_v7(),
            holder_device_id: holder,
            acquired_at: now,
            expires_at,
            renewal_count: 0,
            holder_signature: Ed25519Sig([0u8; 64]),
        };
        *g = Some(record.clone());
        *self.local.lock().expect("lease local") = Some(record.lease_id);
        Ok(record)
    }

    /// F-MD-4 — renew. If the registry's current `lease_id` no longer
    /// matches the one we last wrote, our lease was stolen and the caller
    /// should treat this as `lease.lost`.
    pub fn renew(&self, expires_at: Timestamp) -> Result<LeaseRecord, LeaseError> {
        let local = *self.local.lock().expect("lease local");
        let mut g = self.registry.lock().expect("lease registry");
        let mut rec = g.as_ref().cloned().ok_or(LeaseError::NotHeld)?;
        if Some(rec.lease_id) != local {
            // Someone CAS-overwrote our record. We're no longer the holder.
            *self.local.lock().expect("lease local") = None;
            return Err(LeaseError::Lost);
        }
        rec.expires_at = expires_at;
        rec.renewal_count += 1;
        *g = Some(rec.clone());
        Ok(rec)
    }

    pub fn release(&self) -> Result<(), LeaseError> {
        let local = *self.local.lock().expect("lease local");
        let mut g = self.registry.lock().expect("lease registry");
        let cur_id = g.as_ref().map(|r| r.lease_id);
        if cur_id != local || cur_id.is_none() {
            return Err(LeaseError::NotHeld);
        }
        *g = None;
        *self.local.lock().expect("lease local") = None;
        Ok(())
    }

    /// F-MD-4 Lease Steal. Per spec: a peer may CAS-overwrite the lease
    /// record after observing `expires_at` ≥ 2 × TTL in the past. The TTL
    /// argument is in whole seconds and the staleness check uses the
    /// `epoch:N` form of `Timestamp`. Returns `StillLive` when the
    /// existing lease has not yet aged past the threshold.
    ///
    /// When successful, the prior holder's next `renew` call will fail
    /// with `Lost` and is expected to emit a `lease.lost` event.
    pub fn try_steal(
        &self,
        holder: DeviceId,
        now: Timestamp,
        expires_at: Timestamp,
        ttl_secs: u64,
    ) -> Result<LeaseRecord, LeaseError> {
        let mut g = self.registry.lock().expect("lease registry");
        if let Some(prior) = g.as_ref() {
            let prior_exp = prior.expires_at.epoch_secs();
            let now_secs = now.epoch_secs();
            match (prior_exp, now_secs) {
                (Some(exp), Some(now_s)) => {
                    let aged = now_s.saturating_sub(exp);
                    if aged < 2 * ttl_secs {
                        return Err(LeaseError::StillLive);
                    }
                }
                _ => {
                    // Without parseable timestamps we conservatively refuse
                    // a steal. Tests use `epoch:N`.
                    return Err(LeaseError::StillLive);
                }
            }
        }
        let record = LeaseRecord {
            lease_id: LeaseId::new_v7(),
            holder_device_id: holder,
            acquired_at: now,
            expires_at,
            renewal_count: 0,
            holder_signature: Ed25519Sig([0u8; 64]),
        };
        *g = Some(record.clone());
        *self.local.lock().expect("lease local") = Some(record.lease_id);
        Ok(record)
    }
}

impl Default for LeaseService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_renew_release() {
        let l = LeaseService::new();
        let dev = DeviceId::new_v7();
        let r = l
            .acquire(
                dev,
                Timestamp::from_epoch_secs(0),
                Timestamp::from_epoch_secs(30),
            )
            .unwrap();
        assert_eq!(l.state(), LeaseState::Held);
        let r2 = l.renew(Timestamp::from_epoch_secs(60)).unwrap();
        assert_eq!(r2.lease_id, r.lease_id);
        assert_eq!(r2.renewal_count, 1);
        l.release().unwrap();
        assert_eq!(l.state(), LeaseState::Free);
    }

    #[test]
    fn double_acquire_blocks() {
        let l = LeaseService::new();
        l.acquire(
            DeviceId::new_v7(),
            Timestamp::from_epoch_secs(0),
            Timestamp::from_epoch_secs(30),
        )
        .unwrap();
        let err = l.acquire(
            DeviceId::new_v7(),
            Timestamp::from_epoch_secs(0),
            Timestamp::from_epoch_secs(30),
        );
        assert!(matches!(err, Err(LeaseError::Held)));
    }

    /// F-MD-4 — A held a lease, paused; B observes 2×TTL elapsed and
    /// steals it. A's renew then fails with `Lost`.
    #[test]
    fn steal_after_two_ttl_in_past() {
        let registry = new_registry();
        let a = LeaseService::with_registry(registry.clone());
        let b = LeaseService::with_registry(registry);
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();

        let _ = a
            .acquire(
                dev_a,
                Timestamp::from_epoch_secs(0),
                Timestamp::from_epoch_secs(30),
            )
            .unwrap();
        let ttl = 30u64;
        // Not stale yet (now=60 ⇒ aged=30 = TTL, not 2×TTL).
        let too_soon =
            b.try_steal(dev_b, Timestamp::from_epoch_secs(60), Timestamp::from_epoch_secs(120), ttl);
        assert!(matches!(too_soon, Err(LeaseError::StillLive)));

        // 2×TTL past (now=91 ⇒ aged=61 > 2×TTL=60): steal succeeds.
        let stolen = b
            .try_steal(
                dev_b,
                Timestamp::from_epoch_secs(91),
                Timestamp::from_epoch_secs(121),
                ttl,
            )
            .unwrap();
        assert_eq!(stolen.holder_device_id, dev_b);

        // A's renew now fails with Lost.
        let err = a.renew(Timestamp::from_epoch_secs(150));
        assert!(matches!(err, Err(LeaseError::Lost)));
    }

    /// F-MD-4 — try_steal succeeds when the registry was empty
    /// (equivalent to acquire).
    #[test]
    fn steal_on_empty_registry_takes_lease() {
        let l = LeaseService::new();
        let dev = DeviceId::new_v7();
        let r = l
            .try_steal(
                dev,
                Timestamp::from_epoch_secs(0),
                Timestamp::from_epoch_secs(30),
                30,
            )
            .unwrap();
        assert_eq!(r.holder_device_id, dev);
        assert_eq!(l.state(), LeaseState::Held);
    }
}
