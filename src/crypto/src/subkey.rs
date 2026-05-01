//! HKDF-SHA256 subkey derivation. Each `KeyPurpose` gets its own info string,
//! so subkeys are domain-separated.

use hkdf::Hkdf;
use os_types::KeyPurpose;
use sha2::Sha256;

use crate::{CryptoError, SymKey};

/// Derive a 32-byte subkey from `master` for a given `KeyPurpose`. Optional
/// `context` bytes append to the info parameter for further separation
/// (e.g., chunk index, file id).
pub fn derive_subkey(
    master: &SymKey,
    purpose: KeyPurpose,
    context: Option<&[u8]>,
) -> Result<SymKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = [0u8; 32];
    let info: Vec<u8> = match context {
        Some(c) => {
            let mut v = Vec::with_capacity(purpose.as_bytes().len() + 1 + c.len());
            v.extend_from_slice(purpose.as_bytes());
            v.push(b'|');
            v.extend_from_slice(c);
            v
        }
        None => purpose.as_bytes().to_vec(),
    };
    hk.expand(&info, &mut out)
        .map_err(|_| CryptoError::Input("HKDF expand failed"))?;
    Ok(SymKey::from_bytes(out))
}

/// Derive a per-chunk key from a per-file key. Index goes into the HKDF info
/// so chunks within a file can't be swapped without breaking AEAD AAD.
pub fn derive_chunk_key(file_key: &SymKey, chunk_index: u64) -> Result<SymKey, CryptoError> {
    let ctx = chunk_index.to_be_bytes();
    derive_subkey(file_key, KeyPurpose::FILE, Some(&ctx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> SymKey {
        SymKey::from_bytes([7u8; 32])
    }

    #[test]
    fn purposes_are_independent() {
        let a = derive_subkey(&mk(), KeyPurpose::FILE, None).unwrap();
        let b = derive_subkey(&mk(), KeyPurpose::SHARE_KEM, None).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn chunk_indices_are_independent() {
        let f = derive_subkey(&mk(), KeyPurpose::FILE, None).unwrap();
        let c0 = derive_chunk_key(&f, 0).unwrap();
        let c1 = derive_chunk_key(&f, 1).unwrap();
        assert_ne!(c0.as_bytes(), c1.as_bytes());
    }

    #[test]
    fn deterministic() {
        let a = derive_subkey(&mk(), KeyPurpose::FILE, Some(b"x")).unwrap();
        let b = derive_subkey(&mk(), KeyPurpose::FILE, Some(b"x")).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
