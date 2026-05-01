//! AEAD: ChaCha20-Poly1305 and AES-256-GCM. ChaCha20 is the default; AES is
//! selected when hardware acceleration is present (caller's choice — this
//! module merely implements both).

#[allow(unused_imports)]
use aes_gcm::aead::KeyInit as _;
#[allow(unused_imports)]
use chacha20poly1305::aead::KeyInit as _;
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{Aead as _, AeadCore as _, OsRng, Payload},
    ChaCha20Poly1305,
};
use os_types::{AeadNonce, AeadSuite, AeadTag};

use crate::{CryptoError, SymKey};

/// Encrypt `plaintext` with `key` under `aad`. Output is `(ciphertext, tag)`.
/// Caller supplies the nonce.
pub fn encrypt(
    suite: AeadSuite,
    key: &SymKey,
    nonce: &AeadNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, AeadTag), CryptoError> {
    let nonce_bytes = nonce.as_slice();
    match suite {
        AeadSuite::ChaCha20Poly1305 => {
            if nonce_bytes.len() != 12 {
                return Err(CryptoError::Input("ChaCha20-Poly1305 needs 12-byte nonce"));
            }
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            let mut combined = cipher
                .encrypt(
                    nonce_bytes.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadVerify)?;
            split_tag(&mut combined)
        }
        AeadSuite::Aes256Gcm => {
            if nonce_bytes.len() != 12 {
                return Err(CryptoError::Input("AES-256-GCM needs 12-byte nonce"));
            }
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            let mut combined = cipher
                .encrypt(
                    nonce_bytes.into(),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadVerify)?;
            split_tag(&mut combined)
        }
        AeadSuite::XChaCha20Poly1305 => {
            // Reserved; the type system permits it but we don't have an impl yet.
            Err(CryptoError::Input("XChaCha20-Poly1305 not yet wired"))
        }
    }
}

pub fn decrypt(
    suite: AeadSuite,
    key: &SymKey,
    nonce: &AeadNonce,
    ciphertext: &[u8],
    tag: &AeadTag,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = nonce.as_slice();
    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(&tag.0);
    match suite {
        AeadSuite::ChaCha20Poly1305 => {
            if nonce_bytes.len() != 12 {
                return Err(CryptoError::Input("ChaCha20-Poly1305 needs 12-byte nonce"));
            }
            ChaCha20Poly1305::new(key.as_bytes().into())
                .decrypt(
                    nonce_bytes.into(),
                    Payload {
                        msg: &combined,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadVerify)
        }
        AeadSuite::Aes256Gcm => {
            if nonce_bytes.len() != 12 {
                return Err(CryptoError::Input("AES-256-GCM needs 12-byte nonce"));
            }
            Aes256Gcm::new(key.as_bytes().into())
                .decrypt(
                    nonce_bytes.into(),
                    aes_gcm::aead::Payload {
                        msg: &combined,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadVerify)
        }
        AeadSuite::XChaCha20Poly1305 => Err(CryptoError::Input("XChaCha20-Poly1305 not yet wired")),
    }
}

fn split_tag(combined: &mut Vec<u8>) -> Result<(Vec<u8>, AeadTag), CryptoError> {
    if combined.len() < 16 {
        return Err(CryptoError::Input("AEAD output shorter than tag"));
    }
    let tag_start = combined.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&combined[tag_start..]);
    combined.truncate(tag_start);
    Ok((combined.clone(), AeadTag(tag)))
}

/// Generate a random 12-byte nonce. Use ONLY when the same key is fresh
/// (e.g., per-chunk derived). Repeating a nonce with the same key is fatal.
pub fn random_nonce_12() -> AeadNonce {
    let n = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = [0u8; 12];
    out.copy_from_slice(&n);
    AeadNonce::N12(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymKey {
        SymKey::from_bytes([1u8; 32])
    }

    #[test]
    fn chacha_round_trip() {
        let n = random_nonce_12();
        let (ct, tag) = encrypt(
            AeadSuite::ChaCha20Poly1305,
            &key(),
            &n,
            b"hello world",
            b"aad",
        )
        .unwrap();
        let pt = decrypt(AeadSuite::ChaCha20Poly1305, &key(), &n, &ct, &tag, b"aad").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn aes_round_trip() {
        let n = random_nonce_12();
        let (ct, tag) =
            encrypt(AeadSuite::Aes256Gcm, &key(), &n, b"plaintext", b"aad").unwrap();
        let pt = decrypt(AeadSuite::Aes256Gcm, &key(), &n, &ct, &tag, b"aad").unwrap();
        assert_eq!(pt, b"plaintext");
    }

    #[test]
    fn aad_mismatch_fails() {
        let n = random_nonce_12();
        let (ct, tag) =
            encrypt(AeadSuite::ChaCha20Poly1305, &key(), &n, b"x", b"aad-1").unwrap();
        assert!(decrypt(AeadSuite::ChaCha20Poly1305, &key(), &n, &ct, &tag, b"aad-2").is_err());
    }
}
