//! os-wal — append-only log of CRDT operations + HLC generator.
//!
//! WAL entries are signed by the originating device. The merge path
//! (`os-sync`) is responsible for verifying those signatures; this crate only
//! stores. See `FLOW.md` for invariants.

#![forbid(unsafe_code)]

pub mod hlc;
pub mod log;
pub mod policy;

pub use hlc::HlcGenerator;
pub use log::*;
pub use policy::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalError {
    #[error("entry exceeds wal.max_entry_bytes ({size} > {limit})")]
    EntryTooLarge { size: usize, limit: usize },
    #[error("indirection forbidden for field {0:?}/{1}")]
    IndirectionForbidden(os_entities::KeyKind, String),
    #[error("io: {0}")]
    Io(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("not found at seq {0}")]
    NotFound(u64),
}

impl From<os_crypto::CryptoError> for WalError {
    fn from(e: os_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

pub type Result<T> = std::result::Result<T, WalError>;
