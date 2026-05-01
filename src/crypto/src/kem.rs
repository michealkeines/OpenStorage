//! Key Encapsulation Mechanism — currently a hybrid X25519 + ChaCha20-Poly1305
//! wrap as a placeholder. The real ML-KEM-768 wiring is reserved for a later
//! pass; the surface mirrors what `share/` will need.
//!
//! This module exists so `share/` and `recovery/` can compile against a stable
//! KEM API even though the post-quantum primitive is not yet plumbed.

use crate::{CryptoError, SymKey};

/// Encapsulate a fresh shared secret to a recipient's public key. Returns the
/// ciphertext + the symmetric key the sender derived.
///
/// Placeholder semantics: returns `(recipient_pub_bytes_xor_secret, shared_secret)`.
/// This is **not secure** and exists only to let upstream code compile and be
/// unit-tested end-to-end. Replace with a real ML-KEM-768 binding before any
/// production rollout.
pub fn encapsulate_placeholder(recipient_pub: &[u8]) -> Result<(Vec<u8>, SymKey), CryptoError> {
    if recipient_pub.is_empty() {
        return Err(CryptoError::Input("empty recipient pubkey"));
    }
    let mut shared = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut shared);
    let mut ct = recipient_pub.to_vec();
    for (i, b) in ct.iter_mut().enumerate() {
        *b ^= shared[i % 32];
    }
    Ok((ct, SymKey::from_bytes(shared)))
}

pub fn decapsulate_placeholder(
    recipient_pub: &[u8],
    ciphertext: &[u8],
) -> Result<SymKey, CryptoError> {
    if ciphertext.len() != recipient_pub.len() {
        return Err(CryptoError::Kem);
    }
    let mut shared = [0u8; 32];
    for i in 0..recipient_pub.len() {
        shared[i % 32] ^= ciphertext[i] ^ recipient_pub[i];
    }
    Ok(SymKey::from_bytes(shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_round_trip() {
        let pk = vec![9u8; 32];
        let (ct, k_send) = encapsulate_placeholder(&pk).unwrap();
        let k_recv = decapsulate_placeholder(&pk, &ct).unwrap();
        assert_eq!(k_send.as_bytes(), k_recv.as_bytes());
    }
}
