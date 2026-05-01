//! os-lease — advisory primary-writer lease.
//!
//! Backed by the metadata-vault plugin's `cas_write` capability. This
//! iteration provides the trait + a stub implementation; a real
//! `VaultPluginContract`-backed lease lands when multi-device flows light up.

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Free,
    Held,
}

pub struct LeaseService {
    inner: Arc<Mutex<LeaseInner>>,
}

struct LeaseInner {
    state: LeaseState,
    record: Option<LeaseRecord>,
}

impl LeaseService {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LeaseInner {
                state: LeaseState::Free,
                record: None,
            })),
        }
    }

    pub fn state(&self) -> LeaseState {
        self.inner.lock().expect("lease mutex").state
    }

    pub fn acquire(&self, holder: DeviceId, now: Timestamp, expires_at: Timestamp) -> Result<LeaseRecord, LeaseError> {
        let mut g = self.inner.lock().expect("lease mutex");
        if g.state == LeaseState::Held {
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
        g.state = LeaseState::Held;
        g.record = Some(record.clone());
        Ok(record)
    }

    pub fn renew(&self, expires_at: Timestamp) -> Result<LeaseRecord, LeaseError> {
        let mut g = self.inner.lock().expect("lease mutex");
        let mut rec = g.record.take().ok_or(LeaseError::NotHeld)?;
        rec.expires_at = expires_at;
        rec.renewal_count += 1;
        g.record = Some(rec.clone());
        Ok(rec)
    }

    pub fn release(&self) -> Result<(), LeaseError> {
        let mut g = self.inner.lock().expect("lease mutex");
        if g.state != LeaseState::Held {
            return Err(LeaseError::NotHeld);
        }
        g.state = LeaseState::Free;
        g.record = None;
        Ok(())
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
                Timestamp::from_string("t0"),
                Timestamp::from_string("t1"),
            )
            .unwrap();
        assert_eq!(l.state(), LeaseState::Held);
        let r2 = l.renew(Timestamp::from_string("t2")).unwrap();
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
            Timestamp::from_string("t"),
            Timestamp::from_string("t1"),
        )
        .unwrap();
        let err = l.acquire(
            DeviceId::new_v7(),
            Timestamp::from_string("t"),
            Timestamp::from_string("t1"),
        );
        assert!(matches!(err, Err(LeaseError::Held)));
    }
}
