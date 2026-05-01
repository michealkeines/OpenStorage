//! Internal serde adapters used by fixed-size byte arrays.

use serde::{Deserialize, Deserializer, Serializer};

pub fn ser_array<S, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serde::Serialize::serialize(serde_bytes::Bytes::new(b), s)
}

pub fn de_array<'de, D, const N: usize>(d: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let v: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
    let len = v.len();
    let arr: [u8; N] = v
        .into_vec()
        .try_into()
        .map_err(|_| D::Error::custom(format!("expected {N} bytes, got {len}")))?;
    Ok(arr)
}

pub mod array {
    use super::*;
    pub fn serialize<S, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser_array(b, s)
    }
    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        de_array::<D, N>(d)
    }
}
