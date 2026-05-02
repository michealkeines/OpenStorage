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
pub mod http;
pub mod lifecycle;
pub mod local_dir;
pub mod pool;
pub mod rate_limit;

pub use contract::*;
pub use host::Host;
pub use local_dir::LocalDirPlugin;
pub use pool::{DispatcherConfig, GetDispatched, PoolDispatcher, PutDispatched, RankedCandidate};
pub use rate_limit::{
    CapacitySnapshot, MiddlewarePolicy, Op, RateBucket, RateLimitConfig, RateLimitMiddleware,
    RateLimitProfile, RateLimitStats,
};

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
    /// Backend told us to slow down. The `retry_after` is what the backend
    /// asked for; the rate-limit decorator honors it (or rounds up if zero).
    /// `scope = global` means a per-account cap; `bucket` means a per-key
    /// or per-resource limiter the caller can route around.
    #[error("rate limited; retry after {retry_after:?} ({scope})")]
    RateLimited {
        retry_after: std::time::Duration,
        scope: RateLimitScope,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    /// Account-wide / IP-wide.
    Global,
    /// One specific bucket (e.g., per-channel webhook).
    Bucket,
    /// Backend didn't tell us; assume conservative.
    Unknown,
}

impl std::fmt::Display for RateLimitScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Global => "global",
            Self::Bucket => "bucket",
            Self::Unknown => "unknown",
        })
    }
}

impl PluginError {
    /// Build a `RateLimited` error from the conventional Retry-After
    /// header value (seconds, integer).
    pub fn rate_limited_secs(retry_after_secs: u64, scope: RateLimitScope) -> Self {
        Self::RateLimited {
            retry_after: std::time::Duration::from_secs(retry_after_secs.max(1)),
            scope,
        }
    }
    /// Build a `RateLimited` error from a fractional second (e.g. Discord's
    /// `retry_after: 0.45`).
    pub fn rate_limited_secs_f(retry_after_secs: f64, scope: RateLimitScope) -> Self {
        let ms = (retry_after_secs * 1000.0).max(100.0) as u64;
        Self::RateLimited {
            retry_after: std::time::Duration::from_millis(ms),
            scope,
        }
    }

    /// Best-effort parse of an HTTP `Retry-After` header value (either a
    /// number of seconds or an HTTP-date — we only handle the seconds form).
    pub fn parse_retry_after(value: &str) -> Option<std::time::Duration> {
        value
            .trim()
            .parse::<u64>()
            .ok()
            .map(|s| std::time::Duration::from_secs(s.max(1)))
    }
}

pub type Result<T> = std::result::Result<T, PluginError>;
