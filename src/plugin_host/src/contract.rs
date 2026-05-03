//! Plugin contracts — what every plugin exposes to the host.

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::{
    AeadTag, BlakeHash, CachedElsewhereRisk, CasTier, DeleteOutcome, HealthScore, LatencyProfile,
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

    /// Overwrite an existing handle's bytes in place. The default returns
    /// `NotSupported` so plugins opt in by overriding. The slot pool
    /// (ROUTING.md §5) calls this to reuse a slot's storage instead of
    /// allocating a fresh handle every write.
    ///
    /// Two contracts the implementation must obey:
    ///
    /// - `TrueUpdate` providers (S3, GitHub, R2, …): the returned
    ///   `PutResult.handle` MUST byte-equal `handle`, and
    ///   `handle_changed` MUST be `false`.
    /// - `AtomicReplace` providers: the returned handle MAY differ; the
    ///   plugin SHOULD set `prior_handle_state = Some(Removed)` so the
    ///   slot pool downgrades to a non-reusable record.
    ///
    /// Implementations that don't support either form return
    /// `PluginError::NotSupported`. The slot pool reads this and falls
    /// back to a fresh `put`.
    async fn update(&self, handle: &NativeHandle, payload: &[u8]) -> Result<PutResult> {
        let _ = (handle, payload);
        Err(crate::PluginError::NotSupported(
            "this plugin does not implement update; falling back to put".into(),
        ))
    }

    /// **Self-described rate-limit profile.** The plugin tells the host
    /// everything it knows about its backend's limits — per-op rates,
    /// concurrency, max object size, total quota, and how to recognize a
    /// 429 on the wire — in one declaration. The host reads this once at
    /// registration and wires the rate-limit middleware automatically. New
    /// plugins do not need to know about middleware config; they just say
    /// what their backend is.
    ///
    /// Default = unbounded (suitable for filesystem / in-memory plugins).
    fn rate_limit_profile(&self) -> crate::rate_limit::RateLimitProfile {
        crate::rate_limit::RateLimitProfile::unbounded()
    }
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

    /// Fetch a named blob's contents and current etag. Returns `Ok(None)`
    /// for not-found, distinct from a transport error. Used by the
    /// CAS-backed lease (F-MD-4) and similar small-blob coordination
    /// records.
    async fn named_get(&self, name: &str) -> Result<Option<(Vec<u8>, BlakeHash)>>;

    /// What CAS guarantee this backend offers for `cas_write`. Layer 3 of
    /// `STRUCTURAL_REWORK.md`: the engine refuses to host
    /// snapshot-pointer / lease / WAL records on `EventualOnly` backends.
    /// Default = `OptimisticCas` so existing plugins keep working but
    /// don't get auto-promoted to sole-source coordination duty until
    /// they explicitly declare `StrongCas`.
    fn cas_tier(&self) -> CasTier {
        CasTier::OptimisticCas
    }
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
