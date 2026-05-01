//! WAL entry envelope. The actual `Op` variant is defined here too, since both
//! `wal/` and `sync/` need to reference it without one depending on the other.

use os_types::{
    BlakeHash, DeviceId, Ed25519Sig, FileId, Hlc, IdempotencyKey, LocalKvKey, WalEntryId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalEntry {
    pub wal_id: WalEntryId,
    pub hlc: Hlc,
    pub device_id: DeviceId,
    pub op: Op,
    pub signature: Ed25519Sig,
    pub idempotency_key: Option<IdempotencyKey>,
}

/// CRDT op vocabulary; the `value` byte payloads are CBOR-encoded values whose
/// schema is defined by the `target` Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    #[serde(rename = "lww_set")]
    LwwSet {
        target: Key,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
        #[serde(default, with = "opt_bytes")]
        previous_value: Option<Vec<u8>>,
    },
    #[serde(rename = "lww_register")]
    LwwRegister {
        target: Key,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    #[serde(rename = "lww_register_indirect")]
    LwwRegisterIndirect {
        target: Key,
        value_hash: BlakeHash,
        value_storage_key: LocalKvKey,
        value_size_bytes: u32,
        previous_value_hash: Option<BlakeHash>,
    },
    #[serde(rename = "or_set_add")]
    OrSetAdd {
        target: Key,
        add_id: u128,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    #[serde(rename = "or_set_remove")]
    OrSetRemove {
        target: Key,
        remove_for_add_ids: Vec<u128>,
    },
    #[serde(rename = "counter_inc")]
    CounterInc { target: Key, delta: i64 },
    #[serde(rename = "map_put")]
    MapPut {
        target: Key,
        #[serde(with = "serde_bytes")]
        map_key: Vec<u8>,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    #[serde(rename = "map_del")]
    MapDel {
        target: Key,
        #[serde(with = "serde_bytes")]
        map_key: Vec<u8>,
        remove_for_add_ids: Vec<u128>,
    },
    #[serde(rename = "path_move")]
    PathMove {
        from_path: String,
        to_path: String,
        file_id: FileId,
        linked_remove_id: u128,
        linked_add_id: u128,
    },
}

/// Stable, schema-versioned key under which an op writes. Maps onto a column
/// family and a sub-key in the metadata KV.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Key {
    pub kind: KeyKind,
    /// Big-endian bytes; semantically meaningful per `kind`.
    #[serde(with = "serde_bytes")]
    pub primary: Vec<u8>,
    /// Field discriminator within the entity, e.g. `path`, `wrapped_keys`.
    pub field: String,
}

impl Key {
    pub fn new(kind: KeyKind, primary: Vec<u8>, field: impl Into<String>) -> Self {
        Self {
            kind,
            primary,
            field: field.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyKind {
    #[serde(rename = "vault")]
    Vault,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "chunk")]
    Chunk,
    #[serde(rename = "shard")]
    Shard,
    #[serde(rename = "shadow")]
    Shadow,
    #[serde(rename = "provider")]
    Provider,
    #[serde(rename = "vault_provider")]
    VaultProvider,
    #[serde(rename = "peer")]
    Peer,
    #[serde(rename = "device")]
    Device,
    #[serde(rename = "share")]
    Share,
    #[serde(rename = "identity")]
    Identity,
}

mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match v {
            Some(b) => serde_bytes::Bytes::new(b).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Option<serde_bytes::ByteBuf> = Deserialize::deserialize(d)?;
        Ok(v.map(|b| b.into_vec()))
    }
}
