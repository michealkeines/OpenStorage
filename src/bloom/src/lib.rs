//! os-bloom — per-vault salted Bloom filter for chunk-existence probes.
//!
//! Salt comes from the vault MK under `kp:bloom-salt` (the caller derives it
//! and passes the bytes in). Without the salt the filter's bitfield reveals
//! nothing about chunk hashes.

#![forbid(unsafe_code)]

use os_types::ChunkHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BloomError {
    #[error("bloom not yet sized")]
    NotSized,
}

#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    bit_count: usize,
    k_hashes: u32,
    salt: [u8; 32],
}

impl BloomFilter {
    /// Build for `expected_items` and target false-positive rate `target_fpr`.
    pub fn for_capacity(expected_items: usize, target_fpr: f64, salt: [u8; 32]) -> Self {
        let m = optimal_bits(expected_items, target_fpr);
        let k = optimal_hashes(expected_items, m);
        let words = (m + 63) / 64;
        Self {
            bits: vec![0u64; words.max(1)],
            bit_count: words * 64,
            k_hashes: k,
            salt,
        }
    }

    pub fn add(&mut self, h: ChunkHash) {
        let (h1, h2) = double_hash(&self.salt, h.as_bytes());
        for i in 0..self.k_hashes as u64 {
            let idx = (h1.wrapping_add(i.wrapping_mul(h2)) as usize) % self.bit_count;
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    pub fn contains(&self, h: ChunkHash) -> bool {
        let (h1, h2) = double_hash(&self.salt, h.as_bytes());
        for i in 0..self.k_hashes as u64 {
            let idx = (h1.wrapping_add(i.wrapping_mul(h2)) as usize) % self.bit_count;
            if (self.bits[idx / 64] >> (idx % 64)) & 1 == 0 {
                return false;
            }
        }
        true
    }

    pub fn estimated_count(&self) -> u64 {
        let set: u64 = self.bits.iter().map(|w| w.count_ones() as u64).sum();
        let m = self.bit_count as f64;
        let k = self.k_hashes as f64;
        let frac_unset = 1.0 - (set as f64 / m);
        if frac_unset <= 0.0 {
            return u64::MAX;
        }
        (-(m / k) * frac_unset.ln()).round() as u64
    }

    pub fn bit_count(&self) -> usize {
        self.bit_count
    }
    pub fn k_hashes(&self) -> u32 {
        self.k_hashes
    }
}

fn double_hash(salt: &[u8; 32], data: &[u8]) -> (u64, u64) {
    let mut hasher = blake3::Hasher::new_keyed(salt);
    hasher.update(data);
    let h = hasher.finalize();
    let bytes = h.as_bytes();
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    a.copy_from_slice(&bytes[0..8]);
    b.copy_from_slice(&bytes[8..16]);
    (u64::from_le_bytes(a), u64::from_le_bytes(b) | 1)
}

fn optimal_bits(n: usize, p: f64) -> usize {
    if n == 0 {
        return 64;
    }
    let bits = -((n as f64) * p.ln()) / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
    bits.ceil() as usize
}

fn optimal_hashes(n: usize, m: usize) -> u32 {
    if n == 0 {
        return 1;
    }
    let k = ((m as f64 / n as f64) * std::f64::consts::LN_2).round() as i32;
    k.max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives() {
        let salt = [3u8; 32];
        let mut f = BloomFilter::for_capacity(10_000, 0.01, salt);
        for i in 0u32..10_000 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            f.add(ChunkHash::from_bytes(b));
        }
        for i in 0u32..10_000 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            assert!(f.contains(ChunkHash::from_bytes(b)));
        }
    }

    #[test]
    fn fpr_within_tolerance() {
        let salt = [9u8; 32];
        let mut f = BloomFilter::for_capacity(10_000, 0.01, salt);
        for i in 0u32..10_000 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            f.add(ChunkHash::from_bytes(b));
        }
        let mut fp = 0;
        let trials = 5000;
        for i in 100_000u32..(100_000 + trials) {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            if f.contains(ChunkHash::from_bytes(b)) {
                fp += 1;
            }
        }
        let rate = fp as f64 / trials as f64;
        assert!(rate < 0.05, "FPR {rate} too high");
    }

    #[test]
    fn salt_isolates_filters() {
        let mut a = BloomFilter::for_capacity(100, 0.01, [1u8; 32]);
        let mut b = BloomFilter::for_capacity(100, 0.01, [2u8; 32]);
        for i in 0u32..50 {
            let mut bb = [0u8; 32];
            bb[..4].copy_from_slice(&i.to_le_bytes());
            a.add(ChunkHash::from_bytes(bb));
            b.add(ChunkHash::from_bytes(bb));
        }
        assert_ne!(a.bits, b.bits);
    }
}
