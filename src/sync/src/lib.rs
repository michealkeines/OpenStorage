//! os-sync — CRDT op application and merge.
//!
//! This iteration provides:
//! - `SyncEngine::apply_local_op` — appends a WAL entry and returns it. The
//!   caller is responsible for the corresponding `metadata/` mutation since
//!   the entity-typed put paths live in `os-metadata::Store`. Once we have
//!   multiple devices we'll fold the field-level merge here.
//! - `verify_remote_entry` — signature + HLC-windowed authorization check.
//!
//! Full per-op CRDT field merge is a follow-up; the `Op` cases that VFS uses
//! today (`LwwRegister` on whole-record fields applied via the Store API) are
//! sufficient for the inline-file vertical slice.

#![forbid(unsafe_code)]

use std::sync::Arc;

use os_crypto::verify;
use os_entities::{DeviceAuthorization, OrSet, Op, WalEntry};
use os_types::{DeviceId, Hlc, IdempotencyKey};
use os_wal::Wal;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("wal: {0}")]
    Wal(String),
    #[error("device {0} is not authorized in this vault")]
    UnknownDevice(DeviceId),
    #[error("device {0} not authorized for hlc {1:?}")]
    UnauthorizedHlc(DeviceId, Hlc),
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("serde: {0}")]
    Serde(String),
}

impl From<os_wal::WalError> for SyncError {
    fn from(e: os_wal::WalError) -> Self {
        Self::Wal(e.to_string())
    }
}

pub struct SyncEngine {
    wal: Arc<Wal>,
}

impl SyncEngine {
    pub fn new(wal: Arc<Wal>) -> Self {
        Self { wal }
    }

    pub fn wal(&self) -> Arc<Wal> {
        self.wal.clone()
    }

    /// Append a CRDT op to the local WAL and return the resulting entry. The
    /// caller still mutates `metadata/` via the typed Store — until full
    /// field-level merge lands here, that two-step is explicit.
    pub fn apply_local_op(
        &self,
        op: Op,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<WalEntry, SyncError> {
        let entry = self.wal.append(op, idempotency_key)?;
        Ok(entry)
    }

    /// Verify signature + HLC-window authorization for a foreign WAL entry.
    /// Caller must supply the current `Vault.allowed_devices` set.
    pub fn verify_remote_entry(
        entry: &WalEntry,
        allowed_devices: &OrSet<DeviceAuthorization>,
    ) -> Result<(), SyncError> {
        let auth = allowed_devices
            .live_values()
            .find(|d| d.device_id == entry.device_id)
            .ok_or(SyncError::UnknownDevice(entry.device_id))?;

        if entry.hlc < auth.authorized_from_hlc {
            return Err(SyncError::UnauthorizedHlc(entry.device_id, entry.hlc));
        }
        if let Some(rev) = auth.revoked_at_hlc {
            if entry.hlc >= rev {
                return Err(SyncError::UnauthorizedHlc(entry.device_id, entry.hlc));
            }
        }

        // Re-derive canonical message and verify signature.
        let mut canon = Vec::new();
        ciborium::into_writer(
            &(
                &entry.wal_id,
                entry.hlc,
                entry.device_id,
                &entry.op,
                &entry.idempotency_key,
            ),
            &mut canon,
        )
        .map_err(|e| SyncError::Serde(e.to_string()))?;
        verify(&auth.device_pubkey, &canon, &entry.signature)
            .map_err(|_| SyncError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_crypto::generate_keypair;
    use os_entities::{Key, KeyKind};
    use os_wal::WalBuilder;
    use rand::rngs::OsRng;

    fn open_wal() -> (Arc<Wal>, DeviceId) {
        let mut p = std::env::temp_dir();
        p.push(format!("os-sync-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        let dev = DeviceId::new_v7();
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(p.join("wal.bin"))
            .build(dev, sk)
            .unwrap();
        (Arc::new(wal), dev)
    }

    #[test]
    fn apply_local_op_appends_to_wal() {
        let (wal, _dev) = open_wal();
        let s = SyncEngine::new(wal.clone());
        let op = Op::CounterInc {
            target: Key::new(KeyKind::Chunk, vec![1, 2], "refcount"),
            delta: 1,
        };
        let e = s.apply_local_op(op, None).unwrap();
        assert_eq!(e.wal_id.seq, 0);
        assert_eq!(wal.next_seq(), 1);
    }
}
