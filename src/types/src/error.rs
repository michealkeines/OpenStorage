//! Error taxonomy. Stable on the wire (API §16) and in plugin replies (PLUGIN_SDK §9).

use serde::{Deserialize, Serialize};
use std::fmt;

use super::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // ─── client / preconditions ─────────────────────────────────────────────
    BadRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,

    // ─── vault lifecycle ────────────────────────────────────────────────────
    VaultLocked,
    VaultBusy,
    VaultDestroying,

    // ─── crypto / identity ──────────────────────────────────────────────────
    Corrupted,
    IdentityChainInvalid,
    PeerChainOutdated,
    RecoveryTokenRevoked,
    SignatureInvalid,
    KdfMismatch,

    // ─── lease / coordination ───────────────────────────────────────────────
    LeaseRequired,
    LeaseLost,
    LeaseStolen,

    // ─── plugin / provider ──────────────────────────────────────────────────
    ProviderUnavailable,
    ProviderRateLimited,
    PluginUnhealthy,
    PluginResourceError,
    PluginIdempotencyViolation,
    AuthFailure,
    NotSupported,

    // ─── replication / quorum ───────────────────────────────────────────────
    QuorumUnavailable,
    QuorumWaitTimeout,
    PlacementImpossible,

    // ─── repair / GC ────────────────────────────────────────────────────────
    RepairQueueOverflow,

    // ─── snapshot / vault provider ──────────────────────────────────────────
    SnapshotRollback,
    SnapshotCorrupted,
    SnapshotPointerCasFailed,

    // ─── internal ───────────────────────────────────────────────────────────
    Internal,
    Unimplemented,
}

impl ErrorCode {
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::ProviderUnavailable
                | Self::ProviderRateLimited
                | Self::QuorumWaitTimeout
                | Self::PluginResourceError
                | Self::SnapshotPointerCasFailed
                | Self::VaultBusy
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // serde rename_all = snake_case, so derive a stable wire string.
        let s = match self {
            Self::BadRequest => "bad_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::PreconditionFailed => "precondition_failed",
            Self::VaultLocked => "vault_locked",
            Self::VaultBusy => "vault_busy",
            Self::VaultDestroying => "vault_destroying",
            Self::Corrupted => "corrupted",
            Self::IdentityChainInvalid => "identity_chain_invalid",
            Self::PeerChainOutdated => "peer_chain_outdated",
            Self::RecoveryTokenRevoked => "recovery_token_revoked",
            Self::SignatureInvalid => "signature_invalid",
            Self::KdfMismatch => "kdf_mismatch",
            Self::LeaseRequired => "lease_required",
            Self::LeaseLost => "lease_lost",
            Self::LeaseStolen => "lease_stolen",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::PluginUnhealthy => "plugin_unhealthy",
            Self::PluginResourceError => "plugin_resource_error",
            Self::PluginIdempotencyViolation => "plugin_idempotency_violation",
            Self::AuthFailure => "auth_failure",
            Self::NotSupported => "not_supported",
            Self::QuorumUnavailable => "quorum_unavailable",
            Self::QuorumWaitTimeout => "quorum_wait_timeout",
            Self::PlacementImpossible => "placement_impossible",
            Self::RepairQueueOverflow => "repair_queue_overflow",
            Self::SnapshotRollback => "snapshot_rollback",
            Self::SnapshotCorrupted => "snapshot_corrupted",
            Self::SnapshotPointerCasFailed => "snapshot_pointer_cas_failed",
            Self::Internal => "internal",
            Self::Unimplemented => "unimplemented",
        };
        f.write_str(s)
    }
}

/// Standard error envelope. Returned by API and bubbled internally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub retry_after: Option<Duration>,
    pub details: Option<serde_cbor_value::Value>,
    pub correlation_id: Option<String>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            retryable: code.is_retryable(),
            code,
            message: message.into(),
            retry_after: None,
            details: None,
            correlation_id: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// We want to carry arbitrary structured details without taking a heavy
/// dependency. Fall back to a tiny inline value type aliased to `ciborium::Value`.
mod serde_cbor_value {
    pub type Value = ciborium::Value;
}
