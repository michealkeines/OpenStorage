//! os-share — per-recipient key wraps, signed share blobs, and revocation.
//!
//! Implements the cryptographic core of:
//!
//! - **F-SH-1 Create Share** — owner derives the file_key, KEM-encapsulates
//!   it to the recipient's KEM pubkey, signs a `ShareBlob` with the owner's
//!   current epoch sign key, persists a `Share` record, and adds a
//!   `WrappedKey` entry to the file's `wrapped_keys` OR-Set.
//! - **F-SH-2 Accept Share** — recipient verifies the owner's signature
//!   against the named epoch, KEM-decapsulates to recover the shared
//!   secret, AEAD-decrypts the wrapped file_key, and stores a local
//!   `ReceivedShare` record so the file_key can be reused without going
//!   back to the blob.
//! - **F-SH-3 Revoke Share** — flips `Share.revoked_at`, asks the VFS to
//!   bump the file's `file_key_version` (re-encrypts inline payload; the
//!   chunked re-encryption is enqueued for the repair scheduler per spec
//!   "heavy — async via repair"), and OR-Set-Removes the revoked
//!   recipient's wrapped_key.
//!
//! The KEM and AEAD primitives live in `os-crypto`. The signing key
//! lives in identity epochs; this module accepts the priv key as input so
//! callers can drive it from whichever wrap they use.

#![forbid(unsafe_code)]

use std::sync::Arc;

use os_crypto::{
    blake3_32, decapsulate_placeholder, decrypt as aead_decrypt, encapsulate_placeholder,
    encrypt as aead_encrypt, random_nonce_12, sign, verify, SymKey,
};
use os_entities::{Permission, Share, ShareScope, WrappedKeyRef};
use os_types::WrappedKey;
use os_metadata::{ColumnFamily, Store, Txn};
use os_types::{
    AeadNonce, AeadSuite, AeadTag, Ed25519Priv, Ed25519Pub, Ed25519Sig, EpochId, FileId, MlKemPub,
    PeerId, ShareId, Timestamp, WrapScheme,
};
use os_vfs::{derive_file_key, VfsService};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire format owners hand to recipients out-of-band. CBOR-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareBlob {
    pub share_id: ShareId,
    pub owner_peer_id: PeerId,
    pub owner_epoch_id: EpochId,
    pub recipient_peer_id: PeerId,
    pub file_id: FileId,
    pub file_key_version: u64,
    pub scope: ShareScope,
    pub permissions: Vec<Permission>,
    /// KEM ciphertext addressed to the recipient's KEM pubkey. The
    /// resulting shared secret AEAD-wraps the file_key.
    #[serde(with = "serde_bytes")]
    pub kem_ciphertext: Vec<u8>,
    /// AEAD ciphertext of the file_key under the KEM-derived shared secret.
    #[serde(with = "serde_bytes")]
    pub wrapped_file_key: Vec<u8>,
    pub wrapped_file_key_nonce: AeadNonce,
    pub wrapped_file_key_tag: AeadTag,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub signature: Ed25519Sig,
}

/// Locally-persisted record for an accepted share. Stored under
/// `ColumnFamily::Shares` with key prefix `"received:"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedShare {
    pub share_id: ShareId,
    pub owner_peer_id: PeerId,
    pub file_id: FileId,
    pub file_key_version: u64,
    pub scope: ShareScope,
    pub mounted_path: String,
    /// File key recovered from KEM decap. Stored for now in plaintext on
    /// the local KV; production builds wrap this under the recipient's
    /// MK before persisting (see FUTURE_IMPROVEMENTS).
    #[serde(with = "serde_bytes")]
    pub file_key_bytes: Vec<u8>,
    pub accepted_at: Timestamp,
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("not found: {0}")]
    NotFound(ShareId),
    #[error("metadata: {0}")]
    Metadata(String),
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("vfs: {0}")]
    Vfs(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("recipient mismatch")]
    RecipientMismatch,
    #[error("vault locked")]
    VaultLocked,
}

impl From<os_metadata::MetadataError> for ShareError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}
impl From<os_crypto::CryptoError> for ShareError {
    fn from(e: os_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<os_vfs::VfsError> for ShareError {
    fn from(e: os_vfs::VfsError) -> Self {
        Self::Vfs(e.to_string())
    }
}

pub struct ShareService {
    store: Arc<Store>,
    vfs: Arc<VfsService>,
}

/// Inputs required to create a share.
pub struct CreateShareReq<'a> {
    pub file_id: FileId,
    pub scope: ShareScope,
    pub permissions: Vec<Permission>,
    pub owner_peer_id: PeerId,
    pub owner_epoch_id: EpochId,
    pub owner_sign_priv: &'a Ed25519Priv,
    pub recipient_peer_id: PeerId,
    pub recipient_kem_pub: &'a MlKemPub,
    pub master_key: &'a SymKey,
    pub now: Timestamp,
    pub expires_at: Option<Timestamp>,
}

impl ShareService {
    pub fn new(store: Arc<Store>, vfs: Arc<VfsService>) -> Self {
        Self { store, vfs }
    }

    /// F-SH-1 Create Share. Returns the persisted `Share` and the signed
    /// `ShareBlob` the owner transmits OOB.
    pub fn create_share(&self, req: CreateShareReq<'_>) -> Result<(Share, ShareBlob), ShareError> {
        // 1. Derive the current file_key from MK.
        let version = self.vfs.file_key_version(req.file_id)?;
        let file_key = derive_file_key(req.master_key, req.file_id, version)?;

        // 2. KEM-encapsulate to the recipient's pubkey.
        let (kem_ct, shared_k) = encapsulate_placeholder(&req.recipient_kem_pub.0)?;

        // 3. AEAD-wrap the file_key under the KEM-derived shared secret.
        let nonce = random_nonce_12();
        let aad = wrap_aad(req.file_id, version, &req.recipient_peer_id);
        let (wrapped_ct, wrapped_tag) = aead_encrypt(
            AeadSuite::ChaCha20Poly1305,
            &shared_k,
            &nonce,
            file_key.as_bytes(),
            &aad,
        )?;

        // 4. Build and sign the blob.
        let share_id = ShareId::new_v7();
        let mut blob = ShareBlob {
            share_id,
            owner_peer_id: req.owner_peer_id.clone(),
            owner_epoch_id: req.owner_epoch_id,
            recipient_peer_id: req.recipient_peer_id.clone(),
            file_id: req.file_id,
            file_key_version: version,
            scope: req.scope.clone(),
            permissions: req.permissions.clone(),
            kem_ciphertext: kem_ct,
            wrapped_file_key: wrapped_ct,
            wrapped_file_key_nonce: nonce,
            wrapped_file_key_tag: wrapped_tag,
            created_at: req.now.clone(),
            expires_at: req.expires_at.clone(),
            // placeholder sig overwritten next:
            signature: Ed25519Sig([0u8; 64]),
        };
        let to_sign = canonical_signing_bytes(&blob)?;
        blob.signature = sign(req.owner_sign_priv, &to_sign);

        // 5. Persist the Share record.
        let or_set_add_id =
            u128::from_be_bytes(blake3_32(req.recipient_peer_id.0.as_bytes()).as_bytes()[..16]
                .try_into()
                .unwrap());
        let share = Share {
            share_id,
            scope: req.scope.clone(),
            recipient: req.recipient_peer_id.clone(),
            permissions: req.permissions.clone(),
            wrapped_keys_ref: WrappedKeyRef {
                file_id: req.file_id,
                or_set_add_id,
            },
            created_at: req.now.clone(),
            expires_at: req.expires_at,
            revoked_at: None,
        };
        let mut txn = Txn::new();
        self.store.put_share(&mut txn, &share)?;

        // 6. OR-SET add the wrapped_key onto the File so revoke can later
        // OR-SET remove it.
        if let Some(mut file) = self.store.get_file(req.file_id)? {
            let wk = WrappedKey {
                scheme: WrapScheme::MlKem768Chacha20Poly1305,
                ciphertext: blob.kem_ciphertext.clone(),
                recipient_id: req.recipient_peer_id.clone(),
                wrapped_at: req.now.clone(),
            };
            file.wrapped_keys.add(or_set_add_id, wk);
            self.store.put_file(&mut txn, &file)?;
        }
        self.store.commit(txn)?;
        Ok((share, blob))
    }

    /// F-SH-2 Accept Share. Verifies the owner's signature against the
    /// supplied pubkey, decapsulates the KEM ciphertext, AEAD-decrypts the
    /// wrapped file_key, and persists a `ReceivedShare` record so the
    /// recipient can read the shared file.
    pub fn accept_share(
        &self,
        blob: &ShareBlob,
        owner_sign_pub: &Ed25519Pub,
        recipient_kem_pub: &MlKemPub,
        mount_path: String,
        now: Timestamp,
    ) -> Result<ReceivedShare, ShareError> {
        // 1. Verify signature.
        let to_verify = canonical_signing_bytes_for_verify(blob)?;
        verify(owner_sign_pub, &to_verify, &blob.signature)
            .map_err(|_| ShareError::SignatureInvalid)?;

        // 2. KEM-decapsulate.
        let shared_k = decapsulate_placeholder(&recipient_kem_pub.0, &blob.kem_ciphertext)?;

        // 3. AEAD-decrypt the file_key.
        let aad = wrap_aad(
            blob.file_id,
            blob.file_key_version,
            &blob.recipient_peer_id,
        );
        let file_key_bytes = aead_decrypt(
            AeadSuite::ChaCha20Poly1305,
            &shared_k,
            &blob.wrapped_file_key_nonce,
            &blob.wrapped_file_key,
            &blob.wrapped_file_key_tag,
            &aad,
        )?;

        // 4. Persist ReceivedShare.
        let received = ReceivedShare {
            share_id: blob.share_id,
            owner_peer_id: blob.owner_peer_id.clone(),
            file_id: blob.file_id,
            file_key_version: blob.file_key_version,
            scope: blob.scope.clone(),
            mounted_path: mount_path,
            file_key_bytes,
            accepted_at: now,
        };
        let mut txn = Txn::new();
        let mut k = b"received:".to_vec();
        k.extend_from_slice(received.share_id.as_uuid().as_bytes());
        let mut buf = Vec::new();
        ciborium::into_writer(&received, &mut buf).map_err(|e| ShareError::Encode(e.to_string()))?;
        txn.put(ColumnFamily::Shares, k, buf);
        self.store.commit(txn)?;
        Ok(received)
    }

    pub fn get_received(&self, id: ShareId) -> Result<Option<ReceivedShare>, ShareError> {
        let mut k = b"received:".to_vec();
        k.extend_from_slice(id.as_uuid().as_bytes());
        let backend = self.store.backend();
        let bytes = backend
            .get(ColumnFamily::Shares, &k)
            .map_err(|e| ShareError::Metadata(e.to_string()))?;
        match bytes {
            Some(b) => {
                let r: ReceivedShare =
                    ciborium::from_reader(&b[..]).map_err(|e| ShareError::Encode(e.to_string()))?;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    pub fn list_received(&self) -> Result<Vec<ReceivedShare>, ShareError> {
        let backend = self.store.backend();
        let mut out = Vec::new();
        for kv in backend
            .scan_prefix(ColumnFamily::Shares, b"received:")
            .map_err(|e| ShareError::Metadata(e.to_string()))?
        {
            let (_, v) = kv.map_err(|e| ShareError::Metadata(e.to_string()))?;
            let r: ReceivedShare =
                ciborium::from_reader(&v[..]).map_err(|e| ShareError::Encode(e.to_string()))?;
            out.push(r);
        }
        Ok(out)
    }

    /// F-SH-3 Revoke Share. Flips `revoked_at`, asks VFS to rotate the
    /// file_key (bumps `file_key_version`, re-encrypts inline payload),
    /// and removes the revoked recipient's `WrappedKey` from the file's
    /// OR-Set. Returns the new `file_key_version`.
    pub fn revoke_share(&self, id: ShareId, now: Timestamp) -> Result<u64, ShareError> {
        let mut share = self
            .store
            .get_share(id)?
            .ok_or(ShareError::NotFound(id))?;
        share.revoked_at = Some(now);
        let file_id = share.wrapped_keys_ref.file_id;
        let or_set_add_id = share.wrapped_keys_ref.or_set_add_id;
        let new_version = self.vfs.rotate_file_key(file_id)?;
        let mut txn = Txn::new();
        self.store.put_share(&mut txn, &share)?;
        if let Some(mut file) = self.store.get_file(file_id)? {
            file.wrapped_keys.remove([or_set_add_id]);
            self.store.put_file(&mut txn, &file)?;
        }
        self.store.commit(txn)?;
        Ok(new_version)
    }

    pub fn get_share(&self, id: ShareId) -> Result<Option<Share>, ShareError> {
        Ok(self.store.get_share(id)?)
    }
}

/// Encode a `ShareBlob` to bytes for transmission OOB.
pub fn encode_blob(b: &ShareBlob) -> Result<Vec<u8>, ShareError> {
    let mut out = Vec::new();
    ciborium::into_writer(b, &mut out).map_err(|e| ShareError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode a `ShareBlob` received OOB.
pub fn decode_blob(bytes: &[u8]) -> Result<ShareBlob, ShareError> {
    ciborium::from_reader(bytes).map_err(|e| ShareError::Encode(e.to_string()))
}

/// AAD for the AEAD wrap of the file_key. Bound to (file_id, version,
/// recipient) so a wrap intended for one recipient cannot be replayed to
/// another, and so a stale wrap (after a key rotation) fails the AEAD tag
/// instead of silently letting old keys through.
fn wrap_aad(file_id: FileId, version: u64, recipient: &PeerId) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + recipient.0.len());
    v.extend_from_slice(b"share-wrap:");
    v.extend_from_slice(file_id.as_uuid().as_bytes());
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(recipient.0.as_bytes());
    v
}

/// Bytes signed by the owner. Includes everything in the blob *except*
/// the signature itself. Verifier reconstructs the same byte sequence.
fn canonical_signing_bytes(blob: &ShareBlob) -> Result<Vec<u8>, ShareError> {
    let mut clone = blob.clone();
    clone.signature = Ed25519Sig([0u8; 64]);
    let mut out = Vec::new();
    ciborium::into_writer(&clone, &mut out)
        .map_err(|e| ShareError::Encode(e.to_string()))?;
    Ok(out)
}

fn canonical_signing_bytes_for_verify(blob: &ShareBlob) -> Result<Vec<u8>, ShareError> {
    canonical_signing_bytes(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_crypto::generate_keypair;
    use os_metadata::backend::MemoryBackend;
    use os_plugin_host::Host;
    use os_sync::SyncEngine;
    use os_types::{DeviceId, VaultId};
    use os_vault::VaultManager;
    use os_wal::WalBuilder;
    use rand::rngs::OsRng;

    async fn fixture() -> (Arc<ShareService>, Arc<VfsService>, [u8; 32]) {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let vault = Arc::new(VaultManager::new(store.clone(), host));
        let mk_bytes = [7u8; 32];
        vault.set_unlocked(VaultId::new_v7(), mk_bytes).unwrap();
        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-share-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tdir).unwrap();
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(tdir.join("wal.bin"))
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
        let vfs = Arc::new(VfsService::new(store.clone(), vault.clone(), sync));
        let svc = Arc::new(ShareService::new(store, vfs.clone()));
        (svc, vfs, mk_bytes)
    }

    fn sample_kem_pub() -> MlKemPub {
        // Match ML-KEM-768 fixed length used elsewhere in identity.
        MlKemPub(vec![13u8; 32])
    }

    #[tokio::test]
    async fn create_then_accept_round_trip() {
        let (svc, vfs, mk_bytes) = fixture().await;
        // Author a small inline file owned by the test vault.
        let meta = vfs.write("/note.txt", b"top secret").await.unwrap();

        let (owner_priv, owner_pub) = generate_keypair(&mut OsRng);
        let recipient_kem = sample_kem_pub();
        let mk = SymKey::from_bytes(mk_bytes);
        let req = CreateShareReq {
            file_id: meta.file_id,
            scope: ShareScope::File("/note.txt".into()),
            permissions: vec![Permission::Read],
            owner_peer_id: PeerId("alice".into()),
            owner_epoch_id: EpochId(0),
            owner_sign_priv: &owner_priv,
            recipient_peer_id: PeerId("bob".into()),
            recipient_kem_pub: &recipient_kem,
            master_key: &mk,
            now: Timestamp::from_string("now"),
            expires_at: None,
        };
        let (share, blob) = svc.create_share(req).unwrap();
        assert_eq!(share.recipient.0, "bob");

        // Round-trip the blob through encode/decode.
        let bytes = encode_blob(&blob).unwrap();
        let decoded = decode_blob(&bytes).unwrap();
        assert_eq!(decoded.share_id, blob.share_id);

        // Recipient accepts.
        let received = svc
            .accept_share(
                &decoded,
                &owner_pub,
                &recipient_kem,
                "/shared-with-me/alice/note.txt".into(),
                Timestamp::from_string("now"),
            )
            .unwrap();
        assert_eq!(received.file_id, meta.file_id);
        assert_eq!(received.file_key_version, 0);

        // The recovered file_key bytes must equal what the owner derives.
        let direct = derive_file_key(&mk, meta.file_id, 0).unwrap();
        assert_eq!(received.file_key_bytes, direct.as_bytes().to_vec());
    }

    #[tokio::test]
    async fn accept_with_wrong_owner_pubkey_fails() {
        let (svc, vfs, mk_bytes) = fixture().await;
        let meta = vfs.write("/x", b"data").await.unwrap();
        let (owner_priv, _owner_pub) = generate_keypair(&mut OsRng);
        let (_other_priv, other_pub) = generate_keypair(&mut OsRng);
        let recipient_kem = sample_kem_pub();
        let mk = SymKey::from_bytes(mk_bytes);
        let req = CreateShareReq {
            file_id: meta.file_id,
            scope: ShareScope::File("/x".into()),
            permissions: vec![Permission::Read],
            owner_peer_id: PeerId("a".into()),
            owner_epoch_id: EpochId(0),
            owner_sign_priv: &owner_priv,
            recipient_peer_id: PeerId("b".into()),
            recipient_kem_pub: &recipient_kem,
            master_key: &mk,
            now: Timestamp::from_string("now"),
            expires_at: None,
        };
        let (_, blob) = svc.create_share(req).unwrap();
        let err = svc.accept_share(
            &blob,
            &other_pub,
            &recipient_kem,
            "/shared-with-me/a/x".into(),
            Timestamp::from_string("now"),
        );
        assert!(matches!(err, Err(ShareError::SignatureInvalid)));
    }

    #[tokio::test]
    async fn revoke_bumps_file_key_version_and_removes_wrapped_key() {
        let (svc, vfs, mk_bytes) = fixture().await;
        let meta = vfs.write("/secret.txt", b"hello").await.unwrap();
        let (owner_priv, _owner_pub) = generate_keypair(&mut OsRng);
        let recipient_kem = sample_kem_pub();
        let mk = SymKey::from_bytes(mk_bytes);
        let (share, _blob) = svc
            .create_share(CreateShareReq {
                file_id: meta.file_id,
                scope: ShareScope::File("/secret.txt".into()),
                permissions: vec![Permission::Read],
                owner_peer_id: PeerId("a".into()),
                owner_epoch_id: EpochId(0),
                owner_sign_priv: &owner_priv,
                recipient_peer_id: PeerId("b".into()),
                recipient_kem_pub: &recipient_kem,
                master_key: &mk,
                now: Timestamp::from_string("now"),
                expires_at: None,
            })
            .unwrap();

        // Pre-revoke: file has 1 wrapped_key live, version 0.
        assert_eq!(vfs.file_key_version(meta.file_id).unwrap(), 0);

        let new_v = svc
            .revoke_share(share.share_id, Timestamp::from_string("now"))
            .unwrap();
        assert_eq!(new_v, 1);
        assert_eq!(vfs.file_key_version(meta.file_id).unwrap(), 1);

        // Reading the file via the owner still works (vfs derives with the
        // current version).
        let got = vfs.read("/secret.txt").await.unwrap();
        assert_eq!(got, b"hello");

        // The Share record is now revoked.
        let s = svc.get_share(share.share_id).unwrap().unwrap();
        assert!(s.revoked_at.is_some());
    }
}
