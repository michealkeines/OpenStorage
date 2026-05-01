//! os-keystore — OS secure storage adapter.
//!
//! Two roles:
//! 1. Per-vault MK wrap key (`mk_wrap_<vault_id>`) — set after first successful
//!    unlock; lets subsequent unlocks within a session skip re-derivation.
//! 2. Per-device wrap key (`device_wrap`) — bootstrap-critical; protects the
//!    `VaultBinding` file before any MK exists.
//!
//! See `FLOW.md` for platform layout. This crate provides a `Keystore` trait,
//! an in-memory implementation for tests, and an OS-keyring-backed default.

#![forbid(unsafe_code)]

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("secret not found for {0}")]
    NotFound(String),
    #[error("platform error: {0}")]
    Platform(String),
    #[error("invalid secret length: expected {expected}, got {got}")]
    Length { expected: usize, got: usize },
}

/// 32-byte secret as returned to callers. Zeroized on drop.
pub type Secret = Zeroizing<[u8; 32]>;

pub trait Keystore: Send + Sync {
    fn store(&self, key_id: &str, secret: &[u8; 32]) -> Result<(), KeystoreError>;
    fn load(&self, key_id: &str) -> Result<Secret, KeystoreError>;
    fn delete(&self, key_id: &str) -> Result<(), KeystoreError>;
}

pub mod memory;
pub mod system;
pub mod binding;

pub use memory::MemoryKeystore;
pub use system::SystemKeystore;
