//! os-recovery — vault creation, unlock, MK rotation, destruction.
//!
//! In this iteration: passphrase-only mode is fully wired (Argon2id KDF +
//! AEAD-wrapped MK). RecoveryFile / Shamir / HardwareKey are reserved.
//!
//! The flow:
//! - `new_vault(passphrase)` derives MK from passphrase + Argon2id, generates
//!   a fresh `vault_salt`, builds the Vault record (with a stub
//!   SignedSnapshotPointer + identity epoch from `os-identity`), persists
//!   into `metadata/`, and marks the local `VaultManager` Unlocked with MK.
//! - `unlock(passphrase, vault_id)` reads the persisted Vault + manifest,
//!   re-derives MK, and decrypts the wrapped check-blob to verify.

#![forbid(unsafe_code)]

use std::sync::Arc;

use os_crypto::{
    decrypt as aead_decrypt, derive_master_key, derive_subkey, encrypt as aead_encrypt,
    random_nonce_12, SymKey,
};
use os_entities::{
    OrSet, RecoveryManifest, RecoveryMode, SignedSnapshotPointer, Vault, WrappedMasterKey,
};
use os_identity::IdentityService;
use os_metadata::{Store, Txn};
use os_types::{
    AeadSuite, BlakeHash, Ed25519Sig, EpochId, IdentityId, KdfParams, KeyPurpose,
    MonotonicCounter, RecoveryManifestId, RecoveryTokenId, Timestamp, VaultId,
};
use os_vault::VaultManager;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("metadata: {0}")]
    Metadata(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("vault: {0}")]
    Vault(String),
    #[error("vault {0} not found")]
    VaultNotFound(VaultId),
    #[error("manifest decrypt failed (wrong passphrase?)")]
    Unauthenticated,
    #[error("missing recovery mode: {0}")]
    MissingMode(&'static str),
}

impl From<os_crypto::CryptoError> for RecoveryError {
    fn from(e: os_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<os_metadata::MetadataError> for RecoveryError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}
impl From<os_identity::IdentityError> for RecoveryError {
    fn from(e: os_identity::IdentityError) -> Self {
        Self::Identity(e.to_string())
    }
}
impl From<os_vault::VaultError> for RecoveryError {
    fn from(e: os_vault::VaultError) -> Self {
        Self::Vault(e.to_string())
    }
}

const CHECK_BLOB_AAD: &[u8] = b"openstorage:recovery_manifest:v1";

pub struct RecoveryService {
    store: Arc<Store>,
    identity: Arc<IdentityService>,
    vault: Arc<VaultManager>,
}

impl RecoveryService {
    pub fn new(
        store: Arc<Store>,
        identity: Arc<IdentityService>,
        vault: Arc<VaultManager>,
    ) -> Self {
        Self {
            store,
            identity,
            vault,
        }
    }

    /// Create a new vault from a passphrase. Returns the persisted `Vault`,
    /// the `RecoveryManifest`, and registers the vault as Unlocked on this
    /// device.
    pub fn new_vault(
        &self,
        passphrase: &[u8],
    ) -> Result<(Vault, RecoveryManifest), RecoveryError> {
        let now = Timestamp::from_string("now");
        let kdf_params = test_or_default_kdf_params();
        let mk = derive_master_key(passphrase, &kdf_params)?;
        // Per-vault salt from MK under kp:vault-salt.
        let vault_salt = derive_subkey(&mk, KeyPurpose::VAULT_SALT, None)?;
        let vault_id = VaultId::new_v7();

        // Identity for the vault owner.
        let (identity, _id_priv) = self.identity.create_identity(now.clone())?;
        let owner: IdentityId = identity.identity_id.clone();
        let anchor_fp = identity.epochs[0].fingerprint;

        // RecoveryManifest carrying a wrapped-MK check blob: the wrapped
        // value is a fixed marker that we decrypt under MK during unlock.
        let token_id = RecoveryTokenId::new_v7();
        let nonce = random_nonce_12();
        let (wrapped_check, tag) =
            aead_encrypt(AeadSuite::ChaCha20Poly1305, &mk, &nonce, b"OK", CHECK_BLOB_AAD)?;
        let wrapped_master_key = WrappedMasterKey {
            mode_index: 0,
            recovery_token_id: token_id,
            wrapped: wrapped_check,
            nonce,
            tag,
        };
        let manifest = RecoveryManifest {
            manifest_id: RecoveryManifestId::new_v7(),
            format_version: 1,
            version_counter: MonotonicCounter(1),
            signing_epoch_id: EpochId::ZERO,
            signature: Ed25519Sig([0u8; 64]),
            modes: vec![RecoveryMode::Passphrase],
            wrapped_master_keys: vec![wrapped_master_key],
            identity_anchor_fingerprint: anchor_fp,
            identity_chain: identity.epochs.clone(),
            recovery_token_active_set: {
                let mut s = OrSet::new();
                s.add(token_id.as_uuid().as_u128(), token_id);
                s
            },
        };

        let vault = Vault {
            vault_id,
            format_version: 1,
            owner,
            created_at: now.clone(),
            aead_suite: AeadSuite::ChaCha20Poly1305,
            vault_salt: vault_salt.as_bytes().to_vec(),
            recovery_manifest_ref: manifest.manifest_id,
            snapshot_pointer: SignedSnapshotPointer {
                snapshot_id: vec![0u8; 8],
                version_counter: MonotonicCounter(0),
                epoch_id: EpochId::ZERO,
                format_version: 1,
                created_at: now,
                signature: Ed25519Sig([0u8; 64]),
            },
            lease_path: format!("vaults/{vault_id}/lease.json"),
            allowed_devices: OrSet::new(),
            identity_chain: identity.epochs,
            merkle_root: BlakeHash::from_bytes([0u8; 32]),
        };

        let mut txn = Txn::new();
        self.store.put_vault(&mut txn, &vault)?;
        // We piggy-back the manifest under the same vault_meta cf with a
        // distinct prefix; metadata/Store doesn't yet have a typed manifest
        // accessor — use raw KV.
        let manifest_bytes = encode_cbor(&manifest)?;
        txn.put(
            os_metadata::ColumnFamily::VaultMeta,
            manifest_key(vault_id),
            manifest_bytes,
        );
        txn.put(
            os_metadata::ColumnFamily::VaultMeta,
            kdf_key(vault_id),
            encode_cbor(&kdf_params)?,
        );
        self.store.commit(txn)?;

        let mut mk_bytes = [0u8; 32];
        mk_bytes.copy_from_slice(mk.as_bytes());
        self.vault.set_unlocked(vault_id, mk_bytes)?;

        Ok((vault, manifest))
    }

    /// Unlock an existing vault: re-derive MK, verify check-blob.
    pub fn unlock(
        &self,
        vault_id: VaultId,
        passphrase: &[u8],
    ) -> Result<(), RecoveryError> {
        let backend = self.store.backend();
        let kdf_bytes = backend
            .get(os_metadata::ColumnFamily::VaultMeta, &kdf_key(vault_id))
            .map_err(|e| RecoveryError::Metadata(e.to_string()))?
            .ok_or(RecoveryError::VaultNotFound(vault_id))?;
        let kdf_params: KdfParams = decode_cbor(&kdf_bytes)?;
        let mk = derive_master_key(passphrase, &kdf_params)?;

        let manifest_bytes = backend
            .get(
                os_metadata::ColumnFamily::VaultMeta,
                &manifest_key(vault_id),
            )
            .map_err(|e| RecoveryError::Metadata(e.to_string()))?
            .ok_or(RecoveryError::VaultNotFound(vault_id))?;
        let manifest: RecoveryManifest = decode_cbor(&manifest_bytes)?;

        let wmk = manifest
            .wrapped_master_keys
            .first()
            .ok_or(RecoveryError::MissingMode("passphrase"))?;
        let _: Vec<u8> = aead_decrypt(
            AeadSuite::ChaCha20Poly1305,
            &mk,
            &wmk.nonce,
            &wmk.wrapped,
            &wmk.tag,
            CHECK_BLOB_AAD,
        )
        .map_err(|_| RecoveryError::Unauthenticated)?;

        IdentityService::verify_chain(&manifest.identity_chain, manifest.identity_anchor_fingerprint)
            .map_err(|e| RecoveryError::Identity(e.to_string()))?;

        let mut mk_bytes = [0u8; 32];
        mk_bytes.copy_from_slice(mk.as_bytes());
        self.vault.set_unlocked(vault_id, mk_bytes)?;
        Ok(())
    }

    /// Rotate the master key. Re-derives MK from the new passphrase, re-wraps
    /// the manifest's check-blob, persists, and replaces the in-memory MK.
    pub fn rotate_master_key(
        &self,
        vault_id: VaultId,
        new_passphrase: &[u8],
    ) -> Result<(), RecoveryError> {
        if self.vault.state() != os_vault::VaultState::Unlocked {
            return Err(RecoveryError::Vault("vault must be Unlocked".into()));
        }
        let backend = self.store.backend();
        let manifest_bytes = backend
            .get(os_metadata::ColumnFamily::VaultMeta, &manifest_key(vault_id))
            .map_err(|e| RecoveryError::Metadata(e.to_string()))?
            .ok_or(RecoveryError::VaultNotFound(vault_id))?;
        let mut manifest: RecoveryManifest = decode_cbor(&manifest_bytes)?;

        let new_kdf = test_or_default_kdf_params();
        let new_mk = derive_master_key(new_passphrase, &new_kdf)?;
        // Re-wrap check blob.
        let nonce = random_nonce_12();
        let (wrapped, tag) =
            aead_encrypt(AeadSuite::ChaCha20Poly1305, &new_mk, &nonce, b"OK", CHECK_BLOB_AAD)?;
        let new_token = RecoveryTokenId::new_v7();
        if let Some(wmk) = manifest.wrapped_master_keys.first_mut() {
            wmk.recovery_token_id = new_token;
            wmk.wrapped = wrapped;
            wmk.nonce = nonce;
            wmk.tag = tag;
        } else {
            manifest.wrapped_master_keys.push(WrappedMasterKey {
                mode_index: 0,
                recovery_token_id: new_token,
                wrapped,
                nonce,
                tag,
            });
        }
        manifest.version_counter = MonotonicCounter(manifest.version_counter.0 + 1);
        // Token rotation: revoke old, add new.
        let old_ids: Vec<RecoveryTokenId> = manifest
            .recovery_token_active_set
            .live_values()
            .copied()
            .collect();
        let old_add_ids: Vec<u128> = manifest
            .recovery_token_active_set
            .adds
            .keys()
            .copied()
            .collect();
        let _ = old_ids;
        manifest
            .recovery_token_active_set
            .remove(old_add_ids);
        manifest
            .recovery_token_active_set
            .add(new_token.as_uuid().as_u128(), new_token);

        let mut txn = Txn::new();
        txn.put(
            os_metadata::ColumnFamily::VaultMeta,
            manifest_key(vault_id),
            encode_cbor(&manifest)?,
        );
        txn.put(
            os_metadata::ColumnFamily::VaultMeta,
            kdf_key(vault_id),
            encode_cbor(&new_kdf)?,
        );
        self.store.commit(txn)?;

        let mut mk_bytes = [0u8; 32];
        mk_bytes.copy_from_slice(new_mk.as_bytes());
        self.vault.replace_mk(mk_bytes)?;
        Ok(())
    }

    /// Rotate the active set of recovery tokens without changing MK.
    /// Returns the new token id.
    pub fn rotate_recovery_token(
        &self,
        vault_id: VaultId,
    ) -> Result<RecoveryTokenId, RecoveryError> {
        if self.vault.state() != os_vault::VaultState::Unlocked {
            return Err(RecoveryError::Vault("vault must be Unlocked".into()));
        }
        let backend = self.store.backend();
        let manifest_bytes = backend
            .get(os_metadata::ColumnFamily::VaultMeta, &manifest_key(vault_id))
            .map_err(|e| RecoveryError::Metadata(e.to_string()))?
            .ok_or(RecoveryError::VaultNotFound(vault_id))?;
        let mut manifest: RecoveryManifest = decode_cbor(&manifest_bytes)?;
        let old_add_ids: Vec<u128> = manifest
            .recovery_token_active_set
            .adds
            .keys()
            .copied()
            .collect();
        manifest.recovery_token_active_set.remove(old_add_ids);
        let new_token = RecoveryTokenId::new_v7();
        manifest
            .recovery_token_active_set
            .add(new_token.as_uuid().as_u128(), new_token);
        manifest.version_counter = MonotonicCounter(manifest.version_counter.0 + 1);
        let mut txn = Txn::new();
        txn.put(
            os_metadata::ColumnFamily::VaultMeta,
            manifest_key(vault_id),
            encode_cbor(&manifest)?,
        );
        self.store.commit(txn)?;
        Ok(new_token)
    }

    /// Destroy the vault. Sweeps registered shards via the plugin host (best
    /// effort), zeroizes MK, transitions Unlocked → Destroying → Destroyed.
    pub async fn destroy_vault(&self, vault_id: VaultId) -> Result<DestroyReport, RecoveryError> {
        let cur = self
            .vault
            .vault_id()
            .ok_or(RecoveryError::VaultNotFound(vault_id))?;
        if cur != vault_id {
            return Err(RecoveryError::VaultNotFound(vault_id));
        }
        self.vault
            .begin_destroying()
            .map_err(|e| RecoveryError::Vault(e.to_string()))?;
        let mut report = DestroyReport::default();

        // Sweep shards: for each Shard record, ask its plugin to delete.
        let backend = self.store.backend();
        let shards_iter = backend
            .scan_prefix(os_metadata::ColumnFamily::Shards, b"")
            .map_err(|e| RecoveryError::Metadata(e.to_string()))?;
        for kv in shards_iter {
            let (_k, v) = kv.map_err(|e| RecoveryError::Metadata(e.to_string()))?;
            let shard: os_entities::Shard = decode_cbor(&v)?;
            let provider_id = shard.driver_id.value;
            let plugin = match self.vault.plugin_host().get_chunk(provider_id) {
                Ok(p) => p,
                Err(_) => {
                    report.unknown_shards += 1;
                    continue;
                }
            };
            let handle = shard.native_handle.value.clone();
            match plugin.delete(&handle).await {
                Ok(_) => report.removed_shards += 1,
                Err(_) => report.failed_shards += 1,
            }
        }

        // Wipe metadata records (files, chunks, shards, manifest, kdf).
        let mut txn = Txn::new();
        for cf in [
            os_metadata::ColumnFamily::Files,
            os_metadata::ColumnFamily::Chunks,
            os_metadata::ColumnFamily::Shards,
            os_metadata::ColumnFamily::Shadows,
        ] {
            for kv in backend
                .scan_prefix(cf, b"")
                .map_err(|e| RecoveryError::Metadata(e.to_string()))?
            {
                let (k, _v) = kv.map_err(|e| RecoveryError::Metadata(e.to_string()))?;
                txn.delete(cf, k);
            }
        }
        txn.delete(
            os_metadata::ColumnFamily::VaultMeta,
            manifest_key(vault_id),
        );
        txn.delete(os_metadata::ColumnFamily::VaultMeta, kdf_key(vault_id));
        // Vault entity itself.
        txn.delete(
            os_metadata::ColumnFamily::VaultMeta,
            vault_id.as_uuid().as_bytes().to_vec(),
        );
        self.store.commit(txn)?;

        self.vault
            .finish_destroying()
            .map_err(|e| RecoveryError::Vault(e.to_string()))?;
        Ok(report)
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct DestroyReport {
    pub removed_shards: u64,
    pub failed_shards: u64,
    pub unknown_shards: u64,
}

fn manifest_key(v: VaultId) -> Vec<u8> {
    let mut k = b"manifest:".to_vec();
    k.extend_from_slice(v.as_uuid().as_bytes());
    k
}
fn kdf_key(v: VaultId) -> Vec<u8> {
    let mut k = b"kdf:".to_vec();
    k.extend_from_slice(v.as_uuid().as_bytes());
    k
}

fn encode_cbor<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, RecoveryError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|e| RecoveryError::Metadata(e.to_string()))?;
    Ok(buf)
}

fn decode_cbor<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, RecoveryError> {
    ciborium::from_reader(b).map_err(|e| RecoveryError::Metadata(e.to_string()))
}

fn test_or_default_kdf_params() -> KdfParams {
    if cfg!(test) {
        KdfParams {
            algo: os_types::KdfAlgo::Argon2id,
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            salt: random_salt(16),
        }
    } else {
        os_crypto::default_params(random_salt(16))
    }
}

fn random_salt(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_metadata::backend::MemoryBackend;
    use os_plugin_host::Host;

    fn fixtures() -> Arc<RecoveryService> {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let id = Arc::new(IdentityService::new(store.clone()));
        let vm = Arc::new(VaultManager::new(store.clone(), host));
        Arc::new(RecoveryService::new(store, id, vm))
    }

    #[test]
    fn create_then_unlock_round_trip() {
        let svc = fixtures();
        let (v, _m) = svc.new_vault(b"correct horse").unwrap();
        // Lock the vault, then unlock with the same passphrase.
        svc.vault.lock().unwrap();
        svc.unlock(v.vault_id, b"correct horse").unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Unlocked);
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails() {
        let svc = fixtures();
        let (v, _m) = svc.new_vault(b"good").unwrap();
        svc.vault.lock().unwrap();
        let err = svc.unlock(v.vault_id, b"bad");
        assert!(matches!(err, Err(RecoveryError::Unauthenticated)));
    }

    /// F-VL-2 — explicit unlock-after-lock cycle: state lands on Unlocked.
    #[test]
    fn unlock_after_lock_restores_unlocked_state() {
        let svc = fixtures();
        let (v, _m) = svc.new_vault(b"alpha").unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Unlocked);
        svc.vault.lock().unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Locked);
        svc.unlock(v.vault_id, b"alpha").unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Unlocked);
    }

    /// F-VL-5 — rotate MK: old passphrase no longer unlocks; new one does.
    #[test]
    fn rotate_master_key_invalidates_old_passphrase() {
        let svc = fixtures();
        let (v, _m) = svc.new_vault(b"old-pass").unwrap();
        svc.rotate_master_key(v.vault_id, b"new-pass").unwrap();
        svc.vault.lock().unwrap();
        assert!(matches!(
            svc.unlock(v.vault_id, b"old-pass"),
            Err(RecoveryError::Unauthenticated)
        ));
        svc.unlock(v.vault_id, b"new-pass").unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Unlocked);
    }

    /// 6.A.4 — rotate recovery token: active-set replaces, version_counter bumps.
    #[test]
    fn rotate_recovery_token_updates_active_set() {
        let svc = fixtures();
        let (v, manifest) = svc.new_vault(b"pp").unwrap();
        let initial_count = manifest.recovery_token_active_set.live_values().count();
        let initial_version = manifest.version_counter.0;
        let new_id = svc.rotate_recovery_token(v.vault_id).unwrap();
        // Reload manifest.
        let backend = svc.store.backend();
        let bytes = backend
            .get(os_metadata::ColumnFamily::VaultMeta, &manifest_key(v.vault_id))
            .unwrap()
            .unwrap();
        let m2: RecoveryManifest = decode_cbor(&bytes).unwrap();
        let live: Vec<RecoveryTokenId> =
            m2.recovery_token_active_set.live_values().copied().collect();
        assert_eq!(live, vec![new_id]);
        assert!(m2.version_counter.0 > initial_version);
        let _ = initial_count;
    }

    /// F-VL-4 — destroy_vault transitions to Destroyed and returns a
    /// ResidualReport. The mock plugin host has no chunk plugins so the
    /// sweep finds nothing to remove; the state transition is the contract.
    #[tokio::test]
    async fn destroy_vault_transitions_to_destroyed() {
        let svc = fixtures();
        let (v, _m) = svc.new_vault(b"x").unwrap();
        let report = svc.destroy_vault(v.vault_id).await.unwrap();
        assert_eq!(svc.vault.state(), os_vault::VaultState::Destroyed);
        // Trivial pool: nothing to sweep, no failures expected.
        assert_eq!(report.failed_shards, 0);
    }
}
