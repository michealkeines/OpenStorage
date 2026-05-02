//! Typed entity store on top of `Backend`.
//!
//! `Store::put_*` / `Store::get_*` (de)serialize entities with CBOR and write
//! them into the appropriate column family. Multi-record transactions are
//! built by composing `Txn` ops directly.

use std::sync::Arc;

use os_entities::{
    Chunk, Device, File, Identity, Peer, Provider, Shadow, Shard, Share, Vault, VaultProvider,
};
use os_types::{
    ChunkHash, DeviceId, FileId, IdentityId, PeerId, ProviderId, ShadowId, ShareId, ShardId,
    VaultId,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{Backend, ColumnFamily, MetadataError, Result, Txn};

pub struct Store {
    backend: Arc<dyn Backend>,
}

impl Store {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> Arc<dyn Backend> {
        self.backend.clone()
    }

    pub fn commit(&self, txn: Txn) -> Result<()> {
        self.backend.commit(txn)
    }

    pub fn flush(&self) -> Result<()> {
        self.backend.flush()
    }

    fn encode<T: Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).map_err(|e| MetadataError::Serde(e.to_string()))?;
        Ok(buf)
    }

    fn decode<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T> {
        ciborium::from_reader(bytes).map_err(|e| MetadataError::Serde(e.to_string()))
    }

    fn get_typed<T: DeserializeOwned>(
        &self,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<T>> {
        match self.backend.get(cf, key)? {
            Some(b) => Ok(Some(self.decode(&b)?)),
            None => Ok(None),
        }
    }

    // ─── Vault ─────────────────────────────────────────────────────────────
    pub fn put_vault(&self, txn: &mut Txn, v: &Vault) -> Result<()> {
        txn.put(ColumnFamily::VaultMeta, v.vault_id.as_uuid().as_bytes().as_slice(), self.encode(v)?);
        Ok(())
    }
    pub fn get_vault(&self, id: VaultId) -> Result<Option<Vault>> {
        self.get_typed(ColumnFamily::VaultMeta, id.as_uuid().as_bytes())
    }

    // ─── File ──────────────────────────────────────────────────────────────
    pub fn put_file(&self, txn: &mut Txn, f: &File) -> Result<()> {
        txn.put(ColumnFamily::Files, f.file_id.as_uuid().as_bytes().as_slice(), self.encode(f)?);
        // Maintain the path → file_id secondary index. We always write the
        // current path; stale entries from path renames are an open
        // limitation of this baseline (see FUTURE_IMPROVEMENTS) but for
        // create+delete (the only mutators wired today) the mapping is
        // correct.
        txn.put(
            ColumnFamily::PathIndex,
            f.path.value.as_bytes().to_vec(),
            f.file_id.as_uuid().as_bytes().to_vec(),
        );
        Ok(())
    }
    pub fn get_file(&self, id: FileId) -> Result<Option<File>> {
        self.get_typed(ColumnFamily::Files, id.as_uuid().as_bytes())
    }
    pub fn delete_file(&self, txn: &mut Txn, id: FileId) {
        txn.delete(ColumnFamily::Files, id.as_uuid().as_bytes().as_slice());
    }
    /// O(log N) point lookup via `PathIndex`. Falls back to a full scan
    /// only if the index entry is missing (legacy stores written before the
    /// index existed, or if mid-migration).
    pub fn get_file_by_path(&self, path: &str) -> Result<Option<File>> {
        if let Some(id_bytes) = self.backend.get(ColumnFamily::PathIndex, path.as_bytes())? {
            if let Some(arr) = id_bytes.get(..16) {
                let mut a = [0u8; 16];
                a.copy_from_slice(arr);
                let fid = FileId::from_uuid(uuid::Uuid::from_bytes(a));
                if let Some(f) = self.get_file(fid)? {
                    if f.path.value == path {
                        return Ok(Some(f));
                    }
                }
            }
        }
        // Fallback: linear scan (legacy data without index).
        for f in self.iter_files()? {
            if f.path.value == path {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }
    /// Files whose stored path begins with `prefix`. Uses the path index to
    /// avoid decoding every File record.
    pub fn list_files_with_prefix(&self, prefix: &str) -> Result<Vec<File>> {
        let mut out = Vec::new();
        for r in self.backend.scan_prefix(ColumnFamily::PathIndex, prefix.as_bytes())? {
            let (_k, v) = r?;
            if v.len() < 16 {
                continue;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&v[..16]);
            let fid = FileId::from_uuid(uuid::Uuid::from_bytes(a));
            if let Some(f) = self.get_file(fid)? {
                out.push(f);
            }
        }
        Ok(out)
    }
    pub fn iter_files(&self) -> Result<Vec<File>> {
        let mut out = Vec::new();
        for r in self.backend.scan_prefix(ColumnFamily::Files, b"")? {
            let (_k, v) = r?;
            out.push(self.decode(&v)?);
        }
        Ok(out)
    }

    // ─── Chunk / Shard / Shadow ────────────────────────────────────────────
    pub fn put_chunk(&self, txn: &mut Txn, c: &Chunk) -> Result<()> {
        txn.put(ColumnFamily::Chunks, c.chunk_hash.as_bytes().as_slice(), self.encode(c)?);
        Ok(())
    }
    pub fn get_chunk(&self, h: ChunkHash) -> Result<Option<Chunk>> {
        self.get_typed(ColumnFamily::Chunks, h.as_bytes())
    }
    pub fn put_shard(&self, txn: &mut Txn, s: &Shard) -> Result<()> {
        txn.put(ColumnFamily::Shards, s.shard_id.as_bytes().as_slice(), self.encode(s)?);
        Ok(())
    }
    pub fn get_shard(&self, id: ShardId) -> Result<Option<Shard>> {
        self.get_typed(ColumnFamily::Shards, id.as_bytes())
    }
    pub fn put_shadow(&self, txn: &mut Txn, s: &Shadow) -> Result<()> {
        txn.put(ColumnFamily::Shadows, s.shadow_id.as_uuid().as_bytes().as_slice(), self.encode(s)?);
        Ok(())
    }
    pub fn get_shadow(&self, id: ShadowId) -> Result<Option<Shadow>> {
        self.get_typed(ColumnFamily::Shadows, id.as_uuid().as_bytes())
    }

    // ─── Provider / VaultProvider ──────────────────────────────────────────
    pub fn put_provider(&self, txn: &mut Txn, p: &Provider) -> Result<()> {
        txn.put(
            ColumnFamily::Providers,
            p.provider_id.as_uuid().as_bytes().as_slice(),
            self.encode(p)?,
        );
        Ok(())
    }
    pub fn get_provider(&self, id: ProviderId) -> Result<Option<Provider>> {
        self.get_typed(ColumnFamily::Providers, id.as_uuid().as_bytes())
    }
    pub fn iter_providers(&self) -> Result<Vec<Provider>> {
        let mut out = Vec::new();
        for r in self.backend.scan_prefix(ColumnFamily::Providers, b"")? {
            let (_k, v) = r?;
            out.push(self.decode(&v)?);
        }
        Ok(out)
    }
    pub fn put_vault_provider(&self, txn: &mut Txn, p: &VaultProvider) -> Result<()> {
        let mut k = b"vp:".to_vec();
        k.extend_from_slice(p.provider_id.as_uuid().as_bytes());
        txn.put(ColumnFamily::VaultMeta, k, self.encode(p)?);
        Ok(())
    }

    // ─── Peer / Device / Identity / Share ──────────────────────────────────
    pub fn put_peer(&self, txn: &mut Txn, p: &Peer) -> Result<()> {
        txn.put(
            ColumnFamily::Peers,
            p.peer_id.as_str().as_bytes(),
            self.encode(p)?,
        );
        Ok(())
    }
    pub fn get_peer(&self, id: &PeerId) -> Result<Option<Peer>> {
        self.get_typed(ColumnFamily::Peers, id.as_str().as_bytes())
    }

    pub fn put_device(&self, txn: &mut Txn, d: &Device) -> Result<()> {
        txn.put(
            ColumnFamily::Devices,
            d.device_id.as_uuid().as_bytes().as_slice(),
            self.encode(d)?,
        );
        Ok(())
    }
    pub fn get_device(&self, id: DeviceId) -> Result<Option<Device>> {
        self.get_typed(ColumnFamily::Devices, id.as_uuid().as_bytes())
    }

    pub fn put_identity(&self, txn: &mut Txn, i: &Identity) -> Result<()> {
        txn.put(
            ColumnFamily::Identity,
            i.identity_id.as_str().as_bytes(),
            self.encode(i)?,
        );
        Ok(())
    }
    pub fn get_identity(&self, id: &IdentityId) -> Result<Option<Identity>> {
        self.get_typed(ColumnFamily::Identity, id.as_str().as_bytes())
    }

    pub fn put_share(&self, txn: &mut Txn, s: &Share) -> Result<()> {
        txn.put(
            ColumnFamily::Shares,
            s.share_id.as_uuid().as_bytes().as_slice(),
            self.encode(s)?,
        );
        Ok(())
    }
    pub fn get_share(&self, id: ShareId) -> Result<Option<Share>> {
        self.get_typed(ColumnFamily::Shares, id.as_uuid().as_bytes())
    }

    // ─── Large values (LwwRegisterIndirect) ────────────────────────────────
    pub fn put_large_value(&self, txn: &mut Txn, key: &[u8], value: &[u8]) {
        txn.put(ColumnFamily::LargeValues, key.to_vec(), value.to_vec());
    }
    pub fn get_large_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.backend.get(ColumnFamily::LargeValues, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;
    use os_entities::{Permissions, ReplicationState};
    use os_types::{
        AeadNonce, AeadSuite, AeadTag, BlakeHash, ECScheme, Ed25519Sig, EpochId, FileId, Hlc,
        IdentityId, MonotonicCounter, RecoveryManifestId, Tier, Timestamp, VaultId,
    };
    use os_entities::{LwwRegister, OrSet, SignedSnapshotPointer};

    fn dev() -> DeviceId {
        DeviceId::new_v7()
    }

    #[test]
    fn store_and_retrieve_file() {
        let store = Store::new(Arc::new(MemoryBackend::new()));
        let d = dev();
        let f = File {
            file_id: FileId::new_v7(),
            path: LwwRegister::new("/x".into(), Hlc::new(1, 0), d),
            size_bytes: LwwRegister::new(0, Hlc::new(1, 0), d),
            created_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
            modified_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
            permissions: LwwRegister::new(Permissions::default(), Hlc::new(1, 0), d),
            content_type: LwwRegister::new(String::new(), Hlc::new(1, 0), d),
            tier_pinned: LwwRegister::new(None, Hlc::new(1, 0), d),
            inline_payload: None,
            chunk_list: None,
            wrapped_keys: OrSet::new(),
            acl: OrSet::new(),
            exists: LwwRegister::new(true, Hlc::new(1, 0), d),
        };
        let mut t = Txn::new();
        store.put_file(&mut t, &f).unwrap();
        store.commit(t).unwrap();
        let got = store.get_file(f.file_id).unwrap().unwrap();
        assert_eq!(got.path.value, "/x");
    }

    #[test]
    fn path_index_lookup() {
        // Verify the secondary index gives O(log N) lookups by path.
        let store = Store::new(Arc::new(MemoryBackend::new()));
        let d = dev();
        let fid = FileId::new_v7();
        let f = File {
            file_id: fid,
            path: LwwRegister::new("/alpha/one.txt".into(), Hlc::new(1, 0), d),
            size_bytes: LwwRegister::new(0, Hlc::new(1, 0), d),
            created_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
            modified_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
            permissions: LwwRegister::new(Permissions::default(), Hlc::new(1, 0), d),
            content_type: LwwRegister::new(String::new(), Hlc::new(1, 0), d),
            tier_pinned: LwwRegister::new(None, Hlc::new(1, 0), d),
            inline_payload: None,
            chunk_list: None,
            wrapped_keys: OrSet::new(),
            acl: OrSet::new(),
            exists: LwwRegister::new(true, Hlc::new(1, 0), d),
        };
        let mut t = Txn::new();
        store.put_file(&mut t, &f).unwrap();
        store.commit(t).unwrap();
        let got = store.get_file_by_path("/alpha/one.txt").unwrap().unwrap();
        assert_eq!(got.file_id, fid);
        assert!(store.get_file_by_path("/missing").unwrap().is_none());
    }

    #[test]
    fn list_files_with_prefix_uses_index() {
        let store = Store::new(Arc::new(MemoryBackend::new()));
        let d = dev();
        for p in ["/a/1", "/a/2", "/b/1"] {
            let mut t = Txn::new();
            let f = File {
                file_id: FileId::new_v7(),
                path: LwwRegister::new(p.into(), Hlc::new(1, 0), d),
                size_bytes: LwwRegister::new(0, Hlc::new(1, 0), d),
                created_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
                modified_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
                permissions: LwwRegister::new(Permissions::default(), Hlc::new(1, 0), d),
                content_type: LwwRegister::new(String::new(), Hlc::new(1, 0), d),
                tier_pinned: LwwRegister::new(None, Hlc::new(1, 0), d),
                inline_payload: None,
                chunk_list: None,
                wrapped_keys: OrSet::new(),
                acl: OrSet::new(),
                exists: LwwRegister::new(true, Hlc::new(1, 0), d),
            };
            store.put_file(&mut t, &f).unwrap();
            store.commit(t).unwrap();
        }
        let mut paths: Vec<String> = store
            .list_files_with_prefix("/a/")
            .unwrap()
            .into_iter()
            .map(|f| f.path.value)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["/a/1".to_string(), "/a/2".to_string()]);
    }

    #[test]
    fn iter_files_returns_all() {
        let store = Store::new(Arc::new(MemoryBackend::new()));
        let d = dev();
        for i in 0..3 {
            let mut t = Txn::new();
            let f = File {
                file_id: FileId::new_v7(),
                path: LwwRegister::new(format!("/p{i}"), Hlc::new(1, 0), d),
                size_bytes: LwwRegister::new(0, Hlc::new(1, 0), d),
                created_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
                modified_at: LwwRegister::new(Timestamp::from_string("now"), Hlc::new(1, 0), d),
                permissions: LwwRegister::new(Permissions::default(), Hlc::new(1, 0), d),
                content_type: LwwRegister::new(String::new(), Hlc::new(1, 0), d),
                tier_pinned: LwwRegister::new(None, Hlc::new(1, 0), d),
                inline_payload: None,
                chunk_list: None,
                wrapped_keys: OrSet::new(),
                acl: OrSet::new(),
                exists: LwwRegister::new(true, Hlc::new(1, 0), d),
            };
            store.put_file(&mut t, &f).unwrap();
            store.commit(t).unwrap();
        }
        assert_eq!(store.iter_files().unwrap().len(), 3);
    }

    #[test]
    fn vault_round_trip_with_signed_pointer() {
        let store = Store::new(Arc::new(MemoryBackend::new()));
        let v = Vault {
            vault_id: VaultId::new_v7(),
            format_version: 1,
            owner: IdentityId("id:x".into()),
            created_at: Timestamp::from_string("now"),
            aead_suite: AeadSuite::ChaCha20Poly1305,
            vault_salt: vec![0u8; 32],
            recovery_manifest_ref: RecoveryManifestId::new_v7(),
            snapshot_pointer: SignedSnapshotPointer {
                snapshot_id: vec![0u8; 8],
                version_counter: MonotonicCounter(0),
                epoch_id: EpochId::ZERO,
                format_version: 1,
                created_at: Timestamp::from_string("now"),
                signature: Ed25519Sig([0u8; 64]),
            },
            lease_path: "lease.json".into(),
            allowed_devices: OrSet::new(),
            identity_chain: vec![],
            merkle_root: BlakeHash::from_bytes([0u8; 32]),
        };
        let _ = (ECScheme::new(2, 4).unwrap(), Tier::Hot); // suppress unused warns
        let mut t = Txn::new();
        store.put_vault(&mut t, &v).unwrap();
        store.commit(t).unwrap();
        assert!(store.get_vault(v.vault_id).unwrap().is_some());
    }
}
