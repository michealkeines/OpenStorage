//! os-plugin-host — plugin loading, sandboxing, and the `PluginContract` trait.
//!
//! In this iteration we provide:
//! - The async `PluginContract` and `VaultPluginContract` traits.
//! - An in-process `LocalDirPlugin` that stores objects on the local filesystem
//!   (development / testing / FUSE mode).
//! - A `Host` that dispatches calls by `ProviderId`.
//! WASM sandboxing for third-party plugins is reserved for a follow-up.

#![forbid(unsafe_code)]

pub mod contract;
pub mod host;
pub mod local_dir;

pub use contract::*;
pub use host::Host;
pub use local_dir::LocalDirPlugin;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin not found: {0}")]
    NotFound(String),
    #[error("not supported: {0}")]
    NotSupported(&'static str),
    #[error("auth failure")]
    AuthFailure,
    #[error("io: {0}")]
    Io(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("plugin returned error: {0}")]
    Plugin(String),
    #[error("idempotency violation")]
    IdempotencyViolation,
}

pub type Result<T> = std::result::Result<T, PluginError>;
