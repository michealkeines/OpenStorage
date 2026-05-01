//! os-chunk — pure transform: split, hash, encrypt, EC-encode (and inverse).
//!
//! No orchestration. The caller (`os-vfs`, `os-repair`) drives placement and
//! plugin invocation; this crate computes shards from plaintext and vice versa.

#![forbid(unsafe_code)]

use os_crypto::{decrypt, encrypt, random_nonce_12, SymKey};
use os_ec::{encode as ec_encode, reconstruct as ec_reconstruct, EcError};
use os_types::{
    AeadNonce, AeadSuite, AeadTag, ChunkHash, ECScheme, ShardId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("ec: {0}")]
    Ec(#[from] EcError),
    #[error("shard count mismatch: expected {0}, got {1}")]
    ShardCount(usize, usize),
}

impl From<os_crypto::CryptoError> for ChunkError {
    fn from(e: os_crypto::CryptoError) -> Self {
        ChunkError::Crypto(e)
    }
}

/// Default fixed chunking size (4 MB).
pub const DEFAULT_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Split a contiguous payload into fixed-size chunks. Returns a vec of
/// `(plaintext, chunk_index)`.
pub fn split_fixed(payload: &[u8], chunk_bytes: usize) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    let mut idx = 0u64;
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + chunk_bytes).min(payload.len());
        out.push((payload[off..end].to_vec(), idx));
        off = end;
        idx += 1;
    }
    if out.is_empty() {
        out.push((Vec::new(), 0));
    }
    out
}

/// Compute a chunk hash; mirrors `os_crypto::chunk_hash` for callers that
/// don't want to depend on crypto directly.
pub fn hash(plaintext: &[u8], vault_salt: Option<&[u8]>) -> ChunkHash {
    os_crypto::chunk_hash(plaintext, vault_salt)
}

/// Derive a shard id from `(chunk_hash, shard_index)`.
pub fn shard_id_for(chunk_hash: ChunkHash, shard_index: u8) -> ShardId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(chunk_hash.as_bytes());
    hasher.update(&[shard_index]);
    let h = hasher.finalize();
    ShardId::from_bytes(*h.as_bytes())
}

/// Output of encrypting + EC-encoding a chunk.
#[derive(Debug, Clone)]
pub struct EncodedChunk {
    pub chunk_hash: ChunkHash,
    pub ec_scheme: ECScheme,
    pub nonce: AeadNonce,
    pub tag: AeadTag,
    pub ciphertext_length: u64,
    pub plaintext_length: u64,
    pub shards: Vec<EncodedShard>,
}

#[derive(Debug, Clone)]
pub struct EncodedShard {
    pub shard_id: ShardId,
    pub shard_index: u8,
    pub ciphertext: Vec<u8>,
}

/// Encrypt + EC-encode a single chunk's plaintext.
///
/// AAD = `chunk_hash || shard_index_marker (0xFF for whole-chunk AEAD)`.
/// The whole chunk's ciphertext is what gets EC-encoded; AEAD verification
/// only fires on full reconstruction.
pub fn encrypt_and_encode(
    plaintext: &[u8],
    chunk_hash: ChunkHash,
    chunk_key: &SymKey,
    suite: AeadSuite,
    scheme: ECScheme,
    vault_salt_for_aad: Option<&[u8]>,
) -> Result<EncodedChunk, ChunkError> {
    let _ = vault_salt_for_aad; // reserved for future schemes
    let nonce = random_nonce_12();
    let aad = aad_bytes(chunk_hash);
    let (ciphertext, tag) = encrypt(suite, chunk_key, &nonce, plaintext, &aad)?;
    let ciphertext_length = ciphertext.len() as u64;
    let raw_shards = ec_encode(scheme, &ciphertext)?;
    let mut shards = Vec::with_capacity(raw_shards.len());
    for (i, b) in raw_shards.into_iter().enumerate() {
        let idx = i as u8;
        shards.push(EncodedShard {
            shard_id: shard_id_for(chunk_hash, idx),
            shard_index: idx,
            ciphertext: b,
        });
    }
    Ok(EncodedChunk {
        chunk_hash,
        ec_scheme: scheme,
        nonce,
        tag,
        ciphertext_length,
        plaintext_length: plaintext.len() as u64,
        shards,
    })
}

/// Reverse: take K healthy shard ciphertexts (others as `None`) → reconstruct
/// + decrypt. The caller is responsible for picking which shards to fetch.
pub fn reconstruct_and_decrypt(
    shards: Vec<Option<Vec<u8>>>,
    chunk_hash: ChunkHash,
    chunk_key: &SymKey,
    nonce: &AeadNonce,
    tag: &AeadTag,
    suite: AeadSuite,
    scheme: ECScheme,
    ciphertext_length: u64,
) -> Result<Vec<u8>, ChunkError> {
    let ciphertext = ec_reconstruct(scheme, shards, ciphertext_length as usize)?;
    let aad = aad_bytes(chunk_hash);
    Ok(decrypt(suite, chunk_key, nonce, &ciphertext, tag, &aad)?)
}

/// Inline-blob helper for files at or below the inline threshold.
pub fn pack_inline(
    plaintext: &[u8],
    file_key: &SymKey,
    suite: AeadSuite,
    chunk_hash: ChunkHash,
) -> Result<(Vec<u8>, AeadNonce, AeadTag), ChunkError> {
    let nonce = random_nonce_12();
    let aad = aad_bytes(chunk_hash);
    let (ct, tag) = encrypt(suite, file_key, &nonce, plaintext, &aad)?;
    Ok((ct, nonce, tag))
}

pub fn unpack_inline(
    ciphertext: &[u8],
    file_key: &SymKey,
    nonce: &AeadNonce,
    tag: &AeadTag,
    suite: AeadSuite,
    chunk_hash: ChunkHash,
) -> Result<Vec<u8>, ChunkError> {
    let aad = aad_bytes(chunk_hash);
    Ok(decrypt(suite, file_key, nonce, ciphertext, tag, &aad)?)
}

fn aad_bytes(chunk_hash: ChunkHash) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    v.extend_from_slice(chunk_hash.as_bytes());
    v.push(0xFF);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymKey {
        SymKey::from_bytes([42u8; 32])
    }

    #[test]
    fn split_fixed_basic() {
        let payload = vec![0u8; 10];
        let chunks = split_fixed(&payload, 4);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].1, 0);
        assert_eq!(chunks.last().unwrap().0.len(), 2);
    }

    #[test]
    fn round_trip_with_parity() {
        let pt = b"hello chunked encryption";
        let h = hash(pt, Some(b"salt"));
        let scheme = ECScheme::new(2, 4).unwrap();
        let enc = encrypt_and_encode(pt, h, &key(), AeadSuite::ChaCha20Poly1305, scheme, None)
            .unwrap();
        // simulate dropping shard index 1 and 3
        let mut opt: Vec<Option<Vec<u8>>> = enc
            .shards
            .iter()
            .map(|s| Some(s.ciphertext.clone()))
            .collect();
        opt[1] = None;
        opt[3] = None;
        let out = reconstruct_and_decrypt(
            opt,
            h,
            &key(),
            &enc.nonce,
            &enc.tag,
            AeadSuite::ChaCha20Poly1305,
            scheme,
            enc.ciphertext_length,
        )
        .unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn aad_changes_per_chunk_hash() {
        let pt = b"x";
        let h1 = hash(pt, None);
        let h2 = ChunkHash::from_bytes([0u8; 32]);
        let scheme = ECScheme::new(1, 1).unwrap();
        let enc = encrypt_and_encode(pt, h1, &key(), AeadSuite::ChaCha20Poly1305, scheme, None)
            .unwrap();
        let opt: Vec<Option<Vec<u8>>> = enc
            .shards
            .iter()
            .map(|s| Some(s.ciphertext.clone()))
            .collect();
        // Wrong chunk_hash on decrypt → AEAD AAD mismatch.
        let err = reconstruct_and_decrypt(
            opt,
            h2,
            &key(),
            &enc.nonce,
            &enc.tag,
            AeadSuite::ChaCha20Poly1305,
            scheme,
            enc.ciphertext_length,
        );
        assert!(err.is_err());
    }

    #[test]
    fn inline_round_trip() {
        let pt = b"tiny inline payload";
        let h = hash(pt, None);
        let (ct, n, tag) =
            pack_inline(pt, &key(), AeadSuite::ChaCha20Poly1305, h).unwrap();
        let out = unpack_inline(&ct, &key(), &n, &tag, AeadSuite::ChaCha20Poly1305, h).unwrap();
        assert_eq!(out, pt);
    }
}
