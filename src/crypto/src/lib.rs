//! os-crypto — pure cryptographic byte operations.
//!
//! Implements `CryptoContract` (ABSTRACTIONS §5.2). All keys live only in
//! memory; persistence is handled by `os-keystore`. No I/O of any kind.

#![forbid(unsafe_code)]

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod sig;
pub mod subkey;

pub use aead::*;
pub use hash::*;
pub use kdf::*;
pub use kem::*;
pub use sig::*;
pub use subkey::*;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AEAD verification failed")]
    AeadVerify,
    #[error("KDF parameter rejected: {0}")]
    KdfParam(&'static str),
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("KEM operation failed")]
    Kem,
    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },
    #[error("invalid input: {0}")]
    Input(&'static str),
}

/// 32-byte symmetric key wrapper. Zeroized on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SymKey(pub [u8; 32]);

impl SymKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey(<redacted>)")
    }
}
