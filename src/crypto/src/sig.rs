//! Ed25519 sign / verify wrappers.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use os_types::{Ed25519Priv, Ed25519Pub, Ed25519Sig};
use rand_core::{CryptoRng, RngCore};

use crate::CryptoError;

/// Generate a fresh Ed25519 keypair.
pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Ed25519Priv, Ed25519Pub) {
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let pk: VerifyingKey = sk.verifying_key();
    let pk_bytes = pk.to_bytes();
    (Ed25519Priv(secret), Ed25519Pub(pk_bytes))
}

/// Derive the public Ed25519 key from a private key.
pub fn ed25519_pub_from_priv(priv_key: &Ed25519Priv) -> Ed25519Pub {
    let sk = SigningKey::from_bytes(&priv_key.0);
    let pk: VerifyingKey = sk.verifying_key();
    Ed25519Pub(pk.to_bytes())
}

pub fn sign(priv_key: &Ed25519Priv, message: &[u8]) -> Ed25519Sig {
    let sk = SigningKey::from_bytes(&priv_key.0);
    let sig: Signature = sk.sign(message);
    Ed25519Sig(sig.to_bytes())
}

pub fn verify(pub_key: &Ed25519Pub, message: &[u8], sig: &Ed25519Sig) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&pub_key.0).map_err(|_| CryptoError::SignatureInvalid)?;
    let s = Signature::from_bytes(&sig.0);
    vk.verify(message, &s)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let m = b"hello sig";
        let sig = sign(&sk, m);
        assert!(verify(&pk, m, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let sig = sign(&sk, b"hello sig");
        assert!(verify(&pk, b"helloXsig", &sig).is_err());
    }
}
