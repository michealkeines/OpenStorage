//! VaultBinding wrap/unwrap using the per-device wrap key.
//!
//! Format: `[12-byte nonce | ciphertext | 16-byte tag]`. AEAD is the keystore's
//! choice (ChaCha20-Poly1305 by default); the AAD covers a constant magic
//! string so that bindings can't be confused with other AEAD blobs.
//!
//! The actual `VaultBinding` type lives in `os-entities`. This module is byte-
//! level only; serialization is the caller's responsibility (CBOR via the
//! caller's preferred adapter). We treat the binding as opaque bytes.

use os_crypto::{decrypt, encrypt, SymKey};
use os_types::{AeadNonce, AeadSuite, AeadTag};

use crate::{Keystore, KeystoreError};

const DEVICE_WRAP_ID: &str = "device_wrap";
const BINDING_AAD: &[u8] = b"openstorage:vault_binding:v1";

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("invalid binding payload")]
    Format,
}

impl From<os_crypto::CryptoError> for BindingError {
    fn from(e: os_crypto::CryptoError) -> Self {
        BindingError::Crypto(e)
    }
}

/// Ensure a device wrap key exists in the keystore. Returns the key bytes.
pub fn ensure_device_wrap_key(ks: &dyn Keystore) -> Result<SymKey, BindingError> {
    match ks.load(DEVICE_WRAP_ID) {
        Ok(b) => Ok(SymKey::from_bytes(*b)),
        Err(KeystoreError::NotFound(_)) => {
            use rand::RngCore;
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            ks.store(DEVICE_WRAP_ID, &k)?;
            Ok(SymKey::from_bytes(k))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn wrap_binding(ks: &dyn Keystore, plaintext: &[u8]) -> Result<Vec<u8>, BindingError> {
    let key = ensure_device_wrap_key(ks)?;
    let nonce = os_crypto::random_nonce_12();
    let (ct, tag) = encrypt(
        AeadSuite::ChaCha20Poly1305,
        &key,
        &nonce,
        plaintext,
        BINDING_AAD,
    )?;
    let nonce_bytes = match &nonce {
        AeadNonce::N12(b) => *b,
        _ => return Err(BindingError::Format),
    };
    let mut out = Vec::with_capacity(12 + ct.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag.0);
    Ok(out)
}

pub fn unwrap_binding(ks: &dyn Keystore, blob: &[u8]) -> Result<Vec<u8>, BindingError> {
    if blob.len() < 12 + 16 {
        return Err(BindingError::Format);
    }
    let key = ensure_device_wrap_key(ks)?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&blob[..12]);
    let tag_start = blob.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[tag_start..]);
    let ct = &blob[12..tag_start];
    let pt = decrypt(
        AeadSuite::ChaCha20Poly1305,
        &key,
        &AeadNonce::N12(nonce_bytes),
        ct,
        &AeadTag(tag),
        BINDING_AAD,
    )?;
    Ok(pt)
}

/// Atomic temp-rename write. Caller hands us the parent dir and target name;
/// we serialize, fsync the temp file, then rename.
pub fn atomic_write_binding(
    ks: &dyn Keystore,
    target: &std::path::Path,
    plaintext: &[u8],
) -> Result<(), BindingError> {
    use std::io::Write;
    let blob = wrap_binding(ks, plaintext)?;
    let parent = target
        .parent()
        .ok_or(BindingError::Format)
        .and_then(|p| {
            std::fs::create_dir_all(p)
                .map(|_| p)
                .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))
        })?;
    let tmp = target.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))?;
        f.write_all(&blob)
            .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))?;
        f.sync_all()
            .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))?;
    }
    std::fs::rename(&tmp, target)
        .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))?;
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn read_binding(ks: &dyn Keystore, target: &std::path::Path) -> Result<Vec<u8>, BindingError> {
    let blob = std::fs::read(target)
        .map_err(|e| BindingError::Keystore(KeystoreError::Platform(e.to_string())))?;
    unwrap_binding(ks, &blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryKeystore;

    #[test]
    fn wrap_unwrap_round_trip() {
        let ks = MemoryKeystore::new();
        let blob = wrap_binding(&ks, b"VaultBinding-bytes").unwrap();
        let pt = unwrap_binding(&ks, &blob).unwrap();
        assert_eq!(pt, b"VaultBinding-bytes");
    }

    #[test]
    fn atomic_write_round_trip() {
        let dir = tempdir_for_test();
        let path = dir.join("binding.bin");
        let ks = MemoryKeystore::new();
        atomic_write_binding(&ks, &path, b"payload").unwrap();
        let pt = read_binding(&ks, &path).unwrap();
        assert_eq!(pt, b"payload");
    }

    fn tempdir_for_test() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("os-keystore-test-{}", uuid_v4_simple()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn uuid_v4_simple() -> String {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        hex::encode(b)
    }
}
