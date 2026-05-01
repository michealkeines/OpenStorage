//! Argon2id key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use os_types::{KdfAlgo, KdfParams};

use crate::{CryptoError, SymKey};

/// Derive a 32-byte master key from a passphrase + KDF parameters. Determinism
/// depends on `params.salt`, which the caller is responsible for storing.
pub fn derive_master_key(passphrase: &[u8], params: &KdfParams) -> Result<SymKey, CryptoError> {
    if params.algo != KdfAlgo::Argon2id {
        return Err(CryptoError::KdfParam("only argon2id is supported"));
    }
    let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|_| CryptoError::KdfParam("invalid argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, &params.salt, &mut out)
        .map_err(|_| CryptoError::KdfParam("argon2 derivation failed"))?;
    Ok(SymKey::from_bytes(out))
}

/// Reasonable interactive defaults: 64 MiB, 3 iterations, parallelism 1.
pub fn default_params(salt: Vec<u8>) -> KdfParams {
    KdfParams {
        algo: KdfAlgo::Argon2id,
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
        salt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_salt() {
        // Use a low-cost profile in tests so this stays under a second.
        let params = KdfParams {
            algo: KdfAlgo::Argon2id,
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            salt: b"test-salt-1234567".to_vec(),
        };
        let a = derive_master_key(b"correct horse", &params).unwrap();
        let b = derive_master_key(b"correct horse", &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_changes_output() {
        let make = |salt: &[u8]| KdfParams {
            algo: KdfAlgo::Argon2id,
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            salt: salt.to_vec(),
        };
        let a = derive_master_key(b"pp", &make(b"salt-aaaaaaaaaaaa")).unwrap();
        let b = derive_master_key(b"pp", &make(b"salt-bbbbbbbbbbbb")).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
