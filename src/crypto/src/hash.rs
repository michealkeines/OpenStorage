//! BLAKE3 wrappers.

use os_types::{BlakeHash, ChunkHash};

pub fn blake3_32(input: &[u8]) -> BlakeHash {
    let h = blake3::hash(input);
    BlakeHash::from_bytes(*h.as_bytes())
}

pub fn blake3_keyed_32(key: &[u8; 32], input: &[u8]) -> BlakeHash {
    let h = blake3::keyed_hash(key, input);
    BlakeHash::from_bytes(*h.as_bytes())
}

/// 20-byte fingerprint used in PeerId / IdentityId (truncated BLAKE3-256).
pub fn blake3_160(input: &[u8]) -> [u8; 20] {
    let h = blake3::hash(input);
    let bytes = h.as_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[..20]);
    out
}

/// Compute a chunk hash. If `vault_salt` is Some, hashes `salt || plaintext`
/// (the default mode); otherwise hashes plaintext alone (legacy).
pub fn chunk_hash(plaintext: &[u8], vault_salt: Option<&[u8]>) -> ChunkHash {
    match vault_salt {
        Some(salt) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(salt);
            hasher.update(plaintext);
            ChunkHash::from_bytes(*hasher.finalize().as_bytes())
        }
        None => ChunkHash::from_bytes(*blake3::hash(plaintext).as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_hash_changes_with_salt() {
        let pt = b"hello";
        let a = chunk_hash(pt, None);
        let b = chunk_hash(pt, Some(b"vault-salt"));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn chunk_hash_deterministic() {
        let pt = b"hello";
        let a = chunk_hash(pt, Some(b"s"));
        let b = chunk_hash(pt, Some(b"s"));
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_length() {
        let f = blake3_160(b"x");
        assert_eq!(f.len(), 20);
    }
}
