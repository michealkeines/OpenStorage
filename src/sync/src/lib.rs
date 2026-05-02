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
use os_entities::{
    DeviceAuthorization, KeyKind, LwwRegister, LwwSet, NativeHandle, Op, OrSet, Shadow,
    WalEntry,
};
use os_metadata::{Store, Txn};
use os_types::{
    CachedElsewhereRisk, DeviceId, FileId, Hlc, IdempotencyKey, ShadowId, ShardId, Timestamp,
};
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

impl From<os_metadata::MetadataError> for SyncError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Wal(e.to_string())
    }
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub applied: usize,
    pub lost_to_local: usize,
    pub skipped: usize,
    pub unhandled: usize,
    pub demotions: Vec<ShadowId>,
}

fn decode_file_id(primary: &[u8]) -> Option<FileId> {
    if primary.len() != 16 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(primary);
    Some(FileId::from_uuid(uuid::Uuid::from_bytes(a)))
}

fn decode_shard_id(primary: &[u8]) -> Option<ShardId> {
    if primary.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(primary);
    Some(ShardId::from_bytes(a))
}

fn cmp_hlc_dev(a: (Hlc, DeviceId), b: (Hlc, DeviceId)) -> std::cmp::Ordering {
    match a.0.cmp(&b.0) {
        std::cmp::Ordering::Equal => a.1.0.as_bytes().cmp(b.1.0.as_bytes()),
        o => o,
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

    /// F-MD-5 — apply a batch of foreign WAL entries to the local store.
    ///
    /// Today this handles the field-level merges the spec calls out as
    /// surfaced in user-visible flows:
    ///
    /// - `LwwRegister(file.path)` — F-MD-3 same-`file_id` rename race.
    /// - `LwwRegister(file.exists)` — F-MD-2 update-vs-delete.
    /// - `LwwSet(shard.native_handle, previous_value)` — F-MD-1 concurrent
    ///   update demotion. When the local current handle differs from
    ///   `previous_value` and the remote LwwSet wins HLC-tiebreak, the
    ///   local handle is registered as a `Shadow` with reason
    ///   `ConcurrentUpdateDemoted`.
    ///
    /// Other op kinds are recorded as `unhandled` in the report rather
    /// than failing the whole batch — sync should be progress-monotonic.
    pub fn apply_remote_wal_segment(
        &self,
        store: &Store,
        entries: &[WalEntry],
    ) -> Result<ApplyReport, SyncError> {
        let mut report = ApplyReport::default();
        for entry in entries {
            match &entry.op {
                Op::LwwRegister { target, value } if target.kind == KeyKind::File => {
                    let file_id = match decode_file_id(&target.primary) {
                        Some(f) => f,
                        None => {
                            report.skipped += 1;
                            continue;
                        }
                    };
                    let mut file = match store.get_file(file_id)? {
                        Some(f) => f,
                        None => {
                            report.skipped += 1;
                            continue;
                        }
                    };
                    let mut applied = false;
                    match target.field.as_str() {
                        "path" => {
                            let v: String = ciborium::from_reader(&value[..])
                                .map_err(|e| SyncError::Serde(e.to_string()))?;
                            let remote = LwwRegister::new(v, entry.hlc, entry.device_id);
                            let merged = file.path.clone().merge(remote);
                            if merged != file.path {
                                file.path = merged;
                                applied = true;
                            }
                        }
                        "exists" => {
                            let v: bool = ciborium::from_reader(&value[..])
                                .map_err(|e| SyncError::Serde(e.to_string()))?;
                            let remote = LwwRegister::new(v, entry.hlc, entry.device_id);
                            let merged = file.exists.clone().merge(remote);
                            if merged != file.exists {
                                file.exists = merged;
                                applied = true;
                            }
                        }
                        _ => {
                            report.unhandled += 1;
                            continue;
                        }
                    }
                    if applied {
                        let mut txn = Txn::new();
                        store.put_file(&mut txn, &file)?;
                        store.commit(txn)?;
                        report.applied += 1;
                    } else {
                        report.lost_to_local += 1;
                    }
                }
                Op::LwwSet { target, value, previous_value }
                    if target.kind == KeyKind::Shard
                        && target.field == "native_handle" =>
                {
                    let shard_id = match decode_shard_id(&target.primary) {
                        Some(s) => s,
                        None => {
                            report.skipped += 1;
                            continue;
                        }
                    };
                    let mut shard = match store.get_shard(shard_id)? {
                        Some(s) => s,
                        None => {
                            report.skipped += 1;
                            continue;
                        }
                    };
                    let new_handle: NativeHandle = ciborium::from_reader(&value[..])
                        .map_err(|e| SyncError::Serde(e.to_string()))?;
                    let prev_handle: Option<NativeHandle> = match previous_value {
                        Some(b) => Some(
                            ciborium::from_reader(&b[..])
                                .map_err(|e| SyncError::Serde(e.to_string()))?,
                        ),
                        None => None,
                    };

                    // HLC tiebreak. If local wins, ignore remote.
                    let remote = LwwSet::new(
                        new_handle.clone(),
                        prev_handle.clone(),
                        entry.hlc,
                        entry.device_id,
                    );
                    let local_dominates = match cmp_hlc_dev(
                        (shard.native_handle.hlc, shard.native_handle.device_id),
                        (remote.hlc, remote.device_id),
                    ) {
                        std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => true,
                        std::cmp::Ordering::Less => false,
                    };
                    if local_dominates {
                        report.lost_to_local += 1;
                        continue;
                    }

                    // Remote wins. Compare its previous_value against our
                    // current handle: if they differ, our handle is a
                    // concurrent-update loser and gets demoted to a Shadow
                    // with reason `ConcurrentUpdateDemoted`.
                    let demote = match &prev_handle {
                        Some(prev) if *prev != shard.native_handle.value => true,
                        Some(_) => false,
                        None => shard.native_handle.value != NativeHandle(Vec::new()),
                    };
                    if demote {
                        let shadow = Shadow {
                            shadow_id: ShadowId::new_v7(),
                            original_chunk_hash: shard.chunk_hash,
                            driver_id: shard.driver_id.value,
                            native_handle: shard.native_handle.value.clone(),
                            ciphertext_length: shard.ciphertext_length,
                            abandoned_at: Timestamp::from_string("now"),
                            reason: os_entities::ShadowReason::ConcurrentUpdateDemoted,
                            cached_elsewhere_risk: CachedElsewhereRisk::Low,
                            counts_against_quota: true,
                            tombstone_clears_at: None,
                        };
                        let mut txn = Txn::new();
                        store.put_shadow(&mut txn, &shadow)?;
                        report.demotions.push(shadow.shadow_id);
                        store.commit(txn)?;
                    }
                    shard.native_handle = remote;
                    let mut txn = Txn::new();
                    store.put_shard(&mut txn, &shard)?;
                    store.commit(txn)?;
                    report.applied += 1;
                }
                _ => {
                    report.unhandled += 1;
                }
            }
        }
        Ok(report)
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

    use os_entities::{
        AckState, File, InlineBlob, LwwRegister, OrSet, Permissions, Shard,
    };
    use os_metadata::{backend::MemoryBackend, Store};
    use os_types::{AeadNonce, AeadTag, ChunkHash, HealthScore};

    fn store() -> Arc<Store> {
        Arc::new(Store::new(Arc::new(MemoryBackend::new())))
    }

    fn seed_file(store: &Store, path: &str, hlc: Hlc, dev: DeviceId) -> os_types::FileId {
        let id = os_types::FileId::new_v7();
        let f = File {
            file_id: id,
            path: LwwRegister::new(path.into(), hlc, dev),
            size_bytes: LwwRegister::new(0, hlc, dev),
            created_at: LwwRegister::new(Timestamp::from_string("t0"), hlc, dev),
            modified_at: LwwRegister::new(Timestamp::from_string("t0"), hlc, dev),
            permissions: LwwRegister::new(Permissions::default(), hlc, dev),
            content_type: LwwRegister::new(String::new(), hlc, dev),
            tier_pinned: LwwRegister::new(None, hlc, dev),
            inline_payload: Some(InlineBlob {
                ciphertext: vec![1, 2, 3],
                nonce: AeadNonce::N12([0u8; 12]),
                tag: AeadTag([0u8; 16]),
            }),
            chunk_list: None,
            wrapped_keys: OrSet::new(),
            acl: OrSet::new(),
            exists: LwwRegister::new(true, hlc, dev),
            file_key_version: 0,
        };
        let mut t = os_metadata::Txn::new();
        store.put_file(&mut t, &f).unwrap();
        store.commit(t).unwrap();
        id
    }

    fn make_remote_lww_register_op(
        kind: KeyKind,
        primary: Vec<u8>,
        field: &str,
        value: impl serde::Serialize,
    ) -> Op {
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        Op::LwwRegister {
            target: Key::new(kind, primary, field),
            value: buf,
        }
    }

    fn make_entry(op: Op, hlc: Hlc, device: DeviceId) -> WalEntry {
        WalEntry {
            wal_id: os_types::WalEntryId::new(device, 0),
            hlc,
            device_id: device,
            op,
            signature: os_types::Ed25519Sig([0u8; 64]),
            idempotency_key: None,
        }
    }

    /// F-MD-3 — same-`file_id` rename race: HLC winner's path applies; the
    /// LWW-loser's value is dropped on the local record.
    #[test]
    fn remote_rename_wins_when_hlc_higher() {
        let (wal, _) = open_wal();
        let s = SyncEngine::new(wal);
        let st = store();
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();
        let file_id = seed_file(&st, "/a", Hlc::new(1, 0), dev_a);
        // Remote rename at higher HLC.
        let op = make_remote_lww_register_op(
            KeyKind::File,
            file_id.as_uuid().as_bytes().to_vec(),
            "path",
            "/b",
        );
        let entry = make_entry(op, Hlc::new(2, 0), dev_b);
        let report = s.apply_remote_wal_segment(&st, &[entry]).unwrap();
        assert_eq!(report.applied, 1);
        let f = st.get_file(file_id).unwrap().unwrap();
        assert_eq!(f.path.value, "/b");
    }

    /// F-MD-3 — local HLC > remote: local wins, no change.
    #[test]
    fn local_rename_wins_when_local_hlc_higher() {
        let (wal, _) = open_wal();
        let s = SyncEngine::new(wal);
        let st = store();
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();
        let file_id = seed_file(&st, "/a", Hlc::new(5, 0), dev_a);
        let op = make_remote_lww_register_op(
            KeyKind::File,
            file_id.as_uuid().as_bytes().to_vec(),
            "path",
            "/b",
        );
        let entry = make_entry(op, Hlc::new(2, 0), dev_b);
        let report = s.apply_remote_wal_segment(&st, &[entry]).unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(report.lost_to_local, 1);
        let f = st.get_file(file_id).unwrap().unwrap();
        assert_eq!(f.path.value, "/a");
    }

    /// F-MD-2 — concurrent update (us, lower HLC) vs delete (remote, higher
    /// HLC): exists flips to false on apply.
    #[test]
    fn delete_wins_against_lower_hlc_local() {
        let (wal, _) = open_wal();
        let s = SyncEngine::new(wal);
        let st = store();
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();
        let file_id = seed_file(&st, "/x", Hlc::new(1, 0), dev_a);
        let op = make_remote_lww_register_op(
            KeyKind::File,
            file_id.as_uuid().as_bytes().to_vec(),
            "exists",
            false,
        );
        let entry = make_entry(op, Hlc::new(2, 0), dev_b);
        let report = s.apply_remote_wal_segment(&st, &[entry]).unwrap();
        assert_eq!(report.applied, 1);
        let f = st.get_file(file_id).unwrap().unwrap();
        assert!(!f.exists.value);
    }

    /// F-MD-1 — concurrent update of the same shard handle: remote LwwSet
    /// with `previous_value` matching local current and a fresh new
    /// handle, but local already wrote a *different* new handle. Remote
    /// wins HLC-tiebreak and the local handle is demoted to a Shadow.
    #[test]
    fn concurrent_shard_update_demotes_local_handle() {
        let (wal, _) = open_wal();
        let s = SyncEngine::new(wal);
        let st = store();
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();

        // Seed a Shard with a starting handle (both devices observed).
        let shard_id = ShardId::from_bytes([7u8; 32]);
        let starting = NativeHandle(b"H_old".to_vec());
        let local_new = NativeHandle(b"H_local".to_vec());
        let remote_new = NativeHandle(b"H_remote".to_vec());
        // Local wrote H_local at HLC(2,0).
        let shard = Shard {
            shard_id,
            chunk_hash: ChunkHash::from_bytes([1u8; 32]),
            shard_index: 0,
            encryption_nonce: AeadNonce::N12([0u8; 12]),
            encryption_tag: AeadTag([0u8; 16]),
            ciphertext_length: 0,
            driver_id: LwwSet::new(
                os_types::ProviderId::new_v7(),
                None,
                Hlc::new(1, 0),
                dev_a,
            ),
            native_handle: LwwSet::new(
                local_new.clone(),
                Some(starting.clone()),
                Hlc::new(2, 0),
                dev_a,
            ),
            stored_at: Timestamp::from_string("t0"),
            last_verified_at: Timestamp::from_string("t0"),
            health_score: HealthScore::new(1.0),
            ack_state: AckState::Acked,
        };
        let mut t = os_metadata::Txn::new();
        st.put_shard(&mut t, &shard).unwrap();
        st.commit(t).unwrap();

        // Remote LwwSet at HLC(3,0): new=H_remote, previous_value=H_old.
        let mut value = Vec::new();
        ciborium::into_writer(&remote_new, &mut value).unwrap();
        let mut prev = Vec::new();
        ciborium::into_writer(&starting, &mut prev).unwrap();
        let op = Op::LwwSet {
            target: Key::new(
                KeyKind::Shard,
                shard_id.as_bytes().to_vec(),
                "native_handle",
            ),
            value,
            previous_value: Some(prev),
        };
        let entry = make_entry(op, Hlc::new(3, 0), dev_b);
        let report = s.apply_remote_wal_segment(&st, &[entry]).unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(report.demotions.len(), 1);

        // The shard's native_handle is now H_remote.
        let saved = st.get_shard(shard_id).unwrap().unwrap();
        assert_eq!(saved.native_handle.value, remote_new);

        // Shadow exists with reason ConcurrentUpdateDemoted.
        let shadow = st.get_shadow(report.demotions[0]).unwrap().unwrap();
        assert_eq!(
            shadow.reason,
            os_entities::ShadowReason::ConcurrentUpdateDemoted
        );
        assert_eq!(shadow.native_handle, local_new);
    }

    /// F-MD-1 — local HLC > remote: remote ignored, no demotion.
    #[test]
    fn local_handle_dominates_when_local_hlc_higher() {
        let (wal, _) = open_wal();
        let s = SyncEngine::new(wal);
        let st = store();
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();
        let shard_id = ShardId::from_bytes([8u8; 32]);
        let local_new = NativeHandle(b"H_local".to_vec());
        let starting = NativeHandle(b"H_old".to_vec());
        let shard = Shard {
            shard_id,
            chunk_hash: ChunkHash::from_bytes([1u8; 32]),
            shard_index: 0,
            encryption_nonce: AeadNonce::N12([0u8; 12]),
            encryption_tag: AeadTag([0u8; 16]),
            ciphertext_length: 0,
            driver_id: LwwSet::new(
                os_types::ProviderId::new_v7(),
                None,
                Hlc::new(5, 0),
                dev_a,
            ),
            native_handle: LwwSet::new(
                local_new.clone(),
                Some(starting.clone()),
                Hlc::new(5, 0),
                dev_a,
            ),
            stored_at: Timestamp::from_string("t0"),
            last_verified_at: Timestamp::from_string("t0"),
            health_score: HealthScore::new(1.0),
            ack_state: AckState::Acked,
        };
        let mut t = os_metadata::Txn::new();
        st.put_shard(&mut t, &shard).unwrap();
        st.commit(t).unwrap();

        let remote_new = NativeHandle(b"H_remote".to_vec());
        let mut value = Vec::new();
        ciborium::into_writer(&remote_new, &mut value).unwrap();
        let mut prev = Vec::new();
        ciborium::into_writer(&starting, &mut prev).unwrap();
        let op = Op::LwwSet {
            target: Key::new(
                KeyKind::Shard,
                shard_id.as_bytes().to_vec(),
                "native_handle",
            ),
            value,
            previous_value: Some(prev),
        };
        let entry = make_entry(op, Hlc::new(2, 0), dev_b);
        let report = s.apply_remote_wal_segment(&st, &[entry]).unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(report.lost_to_local, 1);
        assert!(report.demotions.is_empty());
        let saved = st.get_shard(shard_id).unwrap().unwrap();
        assert_eq!(saved.native_handle.value, local_new);
    }
}
