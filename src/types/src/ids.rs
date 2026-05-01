//! Identifiers. Every persistent thing has one of these as its primary key.
//!
//! Conventions:
//! - UUIDv7 wrappers are `Copy` newtypes around `uuid::Uuid`.
//! - String fingerprints (`PeerId`, `IdentityId`, `PluginId`) are interned-ready
//!   newtypes around `String`; equality and hashing are byte-wise on the inner.
//! - `WalEntryId` is the only composite key. It MUST sort `(device_id, seq)`
//!   lexicographically so the metadata KV iteration order matches HLC-aware
//!   replay order on a per-device basis.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[inline]
            pub const fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }
            #[inline]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
            /// Generate a fresh UUIDv7 (time-ordered). Requires `rand` + system clock.
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
    };
}

uuid_id!(VaultId, "Logical namespace; one vault = one user-visible storage realm.");
uuid_id!(FileId, "Stable file identity across renames.");
uuid_id!(ShadowId, "Identifies one orphaned ciphertext object.");
uuid_id!(DeviceId, "First-run-per-device identifier.");
uuid_id!(ShareId, "Per-share record id.");
uuid_id!(ProviderId, "One per configured plugin instance.");
uuid_id!(RecoveryManifestId, "Per-vault recovery manifest id.");
uuid_id!(RecoveryTokenId, "One per generated recovery artifact (file/Shamir share/HW wrap).");
uuid_id!(LeaseId, "Per-acquisition lease id; renew preserves it.");
uuid_id!(IdempotencyKey, "Caller-supplied request dedupe key.");

/// Monotonic identity epoch counter within a single user identity chain.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct EpochId(pub u32);

impl EpochId {
    pub const ZERO: Self = Self(0);
    #[inline]
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

/// `peer:" + base32(BLAKE3-160(sign_pubkey))`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `id:" + base32(BLAKE3-160(epoch_0_sign_pubkey))`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(pub String);

impl IdentityId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reverse-DNS string from the plugin manifest. e.g., `org.openstorage.drive`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginId(pub String);

impl PluginId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 32-byte content hash (BLAKE3-256). For chunks: `H(vault_salt || plaintext)` by default,
/// `H(plaintext)` in legacy mode (see `chunk/FLOW.md`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ChunkHash(#[serde(with = "crate::serde_helpers::array")] pub [u8; 32]);

impl ChunkHash {
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

impl fmt::Display for ChunkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chunk:{}", &self.to_hex()[..16])
    }
}

/// `H(chunk_hash || shard_index)`. 32 bytes; stable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ShardId(#[serde(with = "crate::serde_helpers::array")] pub [u8; 32]);

impl ShardId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard:{}", &hex::encode(self.0)[..16])
    }
}

/// Composite WAL entry identifier. Sorts `(device_id, seq)` lexicographically by
/// the byte representation of `device_id` followed by big-endian `seq`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
pub struct WalEntryId {
    pub device_id: DeviceId,
    pub seq: u64,
}

impl WalEntryId {
    pub fn new(device_id: DeviceId, seq: u64) -> Self {
        Self { device_id, seq }
    }
    /// Big-endian byte form for KV storage; ordering is `(device_id_bytes, seq_be)`.
    pub fn to_key_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..16].copy_from_slice(self.device_id.0.as_bytes());
        out[16..].copy_from_slice(&self.seq.to_be_bytes());
        out
    }
}

impl PartialOrd for WalEntryId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WalEntryId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_key_bytes().cmp(&other.to_key_bytes())
    }
}

impl fmt::Display for WalEntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wal:{}:{}", self.device_id, self.seq)
    }
}

/// Opaque bytes (≤ 64) that the engine returns to plugins instead of raw OAuth tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialsHandle(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl CredentialsHandle {
    pub const MAX_LEN: usize = 64;
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > Self::MAX_LEN {
            return Err("credentials handle exceeds 64 bytes");
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Opaque KV key used by `LwwRegisterIndirect` to point at oversize op values
/// stored separately in metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalKvKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl LocalKvKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_entry_id_orders_lexicographically() {
        let dev = DeviceId::new_v7();
        let a = WalEntryId::new(dev, 1);
        let b = WalEntryId::new(dev, 2);
        assert!(a < b);
        assert_eq!(a.to_key_bytes()[16..], 1u64.to_be_bytes());
    }

    #[test]
    fn uuid_ids_round_trip_cbor() {
        let v = VaultId::new_v7();
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        let v2: VaultId = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn chunk_hash_round_trip_cbor() {
        let h = ChunkHash([7u8; 32]);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf).unwrap();
        let h2: ChunkHash = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn epoch_id_next() {
        assert_eq!(EpochId::ZERO.next(), EpochId(1));
    }

    #[test]
    fn credentials_handle_length_limit() {
        assert!(CredentialsHandle::new(vec![0u8; 64]).is_ok());
        assert!(CredentialsHandle::new(vec![0u8; 65]).is_err());
    }
}
