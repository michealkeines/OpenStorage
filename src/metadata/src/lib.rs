//! os-metadata — embedded LSM KV; the master.
//!
//! Backed by sled in production and an in-memory BTreeMap for tests. Both
//! backends speak the same `Backend` trait, so higher layers can pick.
//!
//! Column families ("trees" in sled parlance):
//! - `files`, `chunks`, `shards`, `shadows`
//! - `peers`, `shares`, `devices`
//! - `vault_meta`, `bloom_state`, `merkle_state`
//! - `wal_index` — secondary index from `WalEntryId` → durable position
//! - `large_values` — payload pool for `LwwRegisterIndirect`
//!
//! Records are CBOR-encoded entity types from `os-entities`.

#![forbid(unsafe_code)]

pub mod backend;
pub mod cf;
pub mod store;

pub use backend::*;
pub use cf::ColumnFamily;
pub use store::Store;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("backend error: {0}")]
    Backend(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("not found: {0}/{1}")]
    NotFound(&'static str, String),
    #[error("transaction conflict")]
    TxnConflict,
}

pub type Result<T> = std::result::Result<T, MetadataError>;
