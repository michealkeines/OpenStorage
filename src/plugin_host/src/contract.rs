//! Plugin contracts — what every plugin exposes to the host.

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::{
    AeadTag, BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    PriorHandleState, QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};

use crate::Result;

#[derive(Debug, Clone)]
pub struct PutResult {
    pub handle: NativeHandle,
    pub handle_changed: bool,
    pub prior_handle_state: Option<PriorHandleState>,
    pub stored_at: Timestamp,
    pub quota_reclaimed: QuotaReclaimed,
    pub tombstone_clears_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct PeekResult {
    pub exists: bool,
    pub size: u64,
    pub mtime: Timestamp,
    pub etag: Option<BlakeHash>,
}

#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub outcome: DeleteOutcome,
    pub quota_reclaimed: QuotaReclaimed,
    pub cached_elsewhere_risk: CachedElsewhereRisk,
    pub tombstone_clears_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct HealthReport {
    pub state: HealthState,
    pub quota: QuotaState,
    pub rate_limit: RateLimitState,
    pub latency: LatencyProfile,
    pub score: HealthScore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

/// AEAD payload bundle that plugins are asked to put. The plugin is opaque to
/// the AEAD: it simply stores the byte vector as one object.
#[derive(Debug, Clone)]
pub struct ObjectBytes {
    pub bytes: Vec<u8>,
    pub tag: AeadTag,
}

#[async_trait]
pub trait PluginContract: Send + Sync {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult>;
    async fn get(&self, handle: &NativeHandle, range: Option<Range>) -> Result<Vec<u8>>;
    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult>;
    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult>;
    async fn health(&self) -> Result<HealthReport>;
}

#[async_trait]
pub trait VaultPluginContract: PluginContract {
    /// `prefix` filters; `cursor` paginates. Implementations MAY return a
    /// truncated page; caller pages with the returned `next_cursor`.
    async fn list(
        &self,
        prefix: &str,
        limit: u32,
        cursor: Option<Vec<u8>>,
    ) -> Result<(Vec<ListEntry>, Option<Vec<u8>>)>;

    /// CAS write: only succeeds if the current etag matches `expected_etag`.
    async fn cas_write(
        &self,
        name: &str,
        payload: &[u8],
        expected_etag: Option<BlakeHash>,
    ) -> Result<CasResult>;
}

#[derive(Debug, Clone)]
pub struct ListEntry {
    pub name: String,
    pub size: u64,
    pub etag: Option<BlakeHash>,
    pub mtime: Timestamp,
}

#[derive(Debug, Clone)]
pub struct CasResult {
    pub outcome: CasOutcome,
    pub new_etag: Option<BlakeHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    Written,
    EtagMismatch,
    NotSupported,
}
