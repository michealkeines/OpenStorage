//! Cryptographic value types — pure shapes only.
//!
//! Sizes are checked at construction. The `crypto/` crate (L2) is responsible
//! for the byte operations themselves.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::time::Timestamp;

/// 32-byte BLAKE3 hash. Generic content addressing / integrity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct BlakeHash(#[serde(with = "crate::serde_helpers::array")] pub [u8; 32]);

impl BlakeHash {
    pub const LEN: usize = 32;
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for BlakeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake:{}", &self.to_hex()[..16])
    }
}

/// AEAD nonce: either 12 bytes (ChaCha20-Poly1305 / AES-GCM) or 24 (XChaCha20).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AeadNonce {
    #[serde(rename = "n12")]
    N12(#[serde(with = "crate::serde_helpers::array")] [u8; 12]),
    #[serde(rename = "n24")]
    N24(#[serde(with = "crate::serde_helpers::array")] [u8; 24]),
}

impl AeadNonce {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            AeadNonce::N12(b) => b,
            AeadNonce::N24(b) => b,
        }
    }
}

/// AEAD authentication tag (16 bytes for both ChaCha20-Poly1305 and AES-GCM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AeadTag(#[serde(with = "crate::serde_helpers::array")] pub [u8; 16]);

/// AEAD cipher suite. Stable on the persistence boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AeadSuite {
    #[serde(rename = "chacha20poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "aes256gcm")]
    Aes256Gcm,
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Pub(#[serde(with = "crate::serde_helpers::array")] pub [u8; 32]);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Ed25519Priv(#[serde(with = "crate::serde_helpers::array")] pub [u8; 32]);

impl fmt::Debug for Ed25519Priv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Priv(<redacted>)")
    }
}

impl PartialEq for Ed25519Priv {
    fn eq(&self, other: &Self) -> bool {
        // constant-time equality is a property of higher-level checks; this
        // exists for testing purposes only.
        self.0 == other.0
    }
}

impl Eq for Ed25519Priv {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Sig(#[serde(with = "crate::serde_helpers::array")] pub [u8; 64]);

/// ML-KEM public key. Variable size depending on parameter set; we store as
/// length-prefixed bytes for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MlKemPub(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct MlKemPriv(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl fmt::Debug for MlKemPriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKemPriv(<redacted>)")
    }
}

impl PartialEq for MlKemPriv {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for MlKemPriv {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MlKemCiphertext(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// One per-recipient wrapping of a file key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub scheme: WrapScheme,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub recipient_id: super::ids::PeerId,
    pub wrapped_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrapScheme {
    #[serde(rename = "mlkem768+chacha20poly1305")]
    MlKem768Chacha20Poly1305,
    #[serde(rename = "x25519+chacha20poly1305")]
    X25519Chacha20Poly1305,
}

/// HKDF info string namespace. Every derived key uses one of these as the info
/// parameter to keep purposes domain-separated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyPurpose(pub &'static str);

impl KeyPurpose {
    pub const VAULT_SALT: Self = Self("kp:vault-salt");
    pub const FILE: Self = Self("kp:file");
    pub const SHARE_KEM: Self = Self("kp:share-kem");
    pub const CRED_WRAP: Self = Self("kp:cred-wrap");
    pub const SNAPSHOT: Self = Self("kp:snapshot");
    pub const WAL_SIGN: Self = Self("kp:wal-sign");
    pub const LEASE_SIGN: Self = Self("kp:lease-sign");
    pub const RECOVERY_TOKEN: Self = Self("kp:recovery-token");

    pub fn as_str(&self) -> &'static str {
        self.0
    }
    pub fn as_bytes(&self) -> &'static [u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Argon2id profile; serialized into the recovery manifest so that re-deriving
/// MK on a different device produces the same key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algo: KdfAlgo,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KdfAlgo {
    #[serde(rename = "argon2id")]
    Argon2id,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_purpose_constants_unique() {
        let all = [
            KeyPurpose::VAULT_SALT,
            KeyPurpose::FILE,
            KeyPurpose::SHARE_KEM,
            KeyPurpose::CRED_WRAP,
            KeyPurpose::SNAPSHOT,
            KeyPurpose::WAL_SIGN,
            KeyPurpose::LEASE_SIGN,
            KeyPurpose::RECOVERY_TOKEN,
        ];
        let mut seen = std::collections::HashSet::new();
        for kp in all {
            assert!(seen.insert(kp.as_str()), "duplicate key purpose: {kp}");
        }
    }

    #[test]
    fn ed25519_priv_debug_redacts() {
        let p = Ed25519Priv([7u8; 32]);
        assert_eq!(format!("{p:?}"), "Ed25519Priv(<redacted>)");
    }

    #[test]
    fn aead_nonce_serializes_round_trip() {
        let n = AeadNonce::N12([3u8; 12]);
        let mut buf = Vec::new();
        ciborium::into_writer(&n, &mut buf).unwrap();
        let n2: AeadNonce = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(n, n2);
    }
}
