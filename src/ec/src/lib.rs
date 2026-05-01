//! os-ec — Reed–Solomon erasure coding. Pure computation; no I/O.

#![forbid(unsafe_code)]

use os_types::ECScheme;
use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EcError {
    #[error("invalid scheme: {0}")]
    Scheme(String),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("reconstruct failed: {0}")]
    Reconstruct(String),
    #[error("insufficient shards: have {have}, need {need}")]
    InsufficientShards { have: usize, need: usize },
}

/// Encode `payload` into N shards. Each shard is `ceil(len/k)` bytes; the
/// final data shard is zero-padded if `len` is not divisible by k. The
/// payload length is *not* stored here — the caller is responsible for
/// remembering it so reconstruct can trim the result.
pub fn encode(scheme: ECScheme, payload: &[u8]) -> Result<Vec<Vec<u8>>, EcError> {
    let k = scheme.k as usize;
    let n = scheme.n as usize;
    let parity = n - k;
    if k == 0 || k > n {
        return Err(EcError::Scheme(format!("invalid k/n: {}/{}", k, n)));
    }
    if k == n {
        // (1,1) and (k,k): no parity. Produce k data shards directly.
        return Ok(split_into_k(payload, k));
    }
    let r = ReedSolomon::new(k, parity).map_err(|e| EcError::Scheme(e.to_string()))?;
    let mut shards = split_into_k(payload, k);
    let shard_len = shards[0].len();
    for _ in 0..parity {
        shards.push(vec![0u8; shard_len]);
    }
    r.encode(&mut shards).map_err(|e| EcError::Encode(e.to_string()))?;
    Ok(shards)
}

/// Reconstruct from any K healthy shards. `shards_in[i]` corresponds to
/// shard_index `i`; pass `None` for missing shards. Returns the concatenated
/// data bytes (length = `original_len`).
pub fn reconstruct(
    scheme: ECScheme,
    mut shards_in: Vec<Option<Vec<u8>>>,
    original_len: usize,
) -> Result<Vec<u8>, EcError> {
    let k = scheme.k as usize;
    let n = scheme.n as usize;
    if shards_in.len() != n {
        return Err(EcError::Reconstruct(format!(
            "expected {n} shard slots, got {}",
            shards_in.len()
        )));
    }
    let have = shards_in.iter().filter(|s| s.is_some()).count();
    if have < k {
        return Err(EcError::InsufficientShards { have, need: k });
    }
    if k == n {
        // No parity — every data shard is required.
        let mut out = Vec::with_capacity(original_len);
        for shard in shards_in.iter_mut().take(k) {
            let s = shard.take().ok_or(EcError::InsufficientShards {
                have: k - 1,
                need: k,
            })?;
            out.extend(s);
        }
        out.truncate(original_len);
        return Ok(out);
    }
    let parity = n - k;
    let r = ReedSolomon::new(k, parity).map_err(|e| EcError::Scheme(e.to_string()))?;
    r.reconstruct(&mut shards_in)
        .map_err(|e| EcError::Reconstruct(e.to_string()))?;
    let mut out = Vec::with_capacity(original_len);
    for shard in shards_in.iter().take(k) {
        out.extend(shard.as_ref().expect("reconstruct fills data shards"));
    }
    out.truncate(original_len);
    Ok(out)
}

fn split_into_k(payload: &[u8], k: usize) -> Vec<Vec<u8>> {
    let shard_len = (payload.len() + k - 1) / k;
    let shard_len = shard_len.max(1);
    let mut out = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * shard_len;
        let end = (start + shard_len).min(payload.len());
        let mut s = vec![0u8; shard_len];
        if start < payload.len() {
            s[..end - start].copy_from_slice(&payload[start..end]);
        }
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_with_drops(scheme: ECScheme, payload: &[u8], drop: &[usize]) {
        let shards = encode(scheme, payload).unwrap();
        assert_eq!(shards.len(), scheme.n as usize);
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for &i in drop {
            opt[i] = None;
        }
        let out = reconstruct(scheme, opt, payload.len()).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn k2_n4_drops_two_parity() {
        let s = ECScheme::new(2, 4).unwrap();
        round_trip_with_drops(s, b"hello erasure coding world!", &[2, 3]);
    }

    #[test]
    fn k3_n5_drops_two_arbitrary() {
        let s = ECScheme::new(3, 5).unwrap();
        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        round_trip_with_drops(s, &payload, &[0, 4]);
    }

    #[test]
    fn replication_k1_n3() {
        let s = ECScheme::replication(3);
        round_trip_with_drops(s, b"abc", &[0, 2]);
    }

    #[test]
    fn insufficient_shards_fails() {
        let s = ECScheme::new(3, 5).unwrap();
        let shards = encode(s, b"abcdefghij").unwrap();
        let opt: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .enumerate()
            .map(|(i, s)| if i < 2 { Some(s) } else { None })
            .collect();
        assert!(matches!(
            reconstruct(s, opt, 10),
            Err(EcError::InsufficientShards { .. })
        ));
    }
}
