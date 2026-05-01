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
}
