//! Health-recording plugin wrappers.
//!
//! Layer 2 closure (per `STRUCTURAL_REWORK.md` drift item #3): every
//! `plugin.put / get / peek / delete` (and the vault-side `cas_write`,
//! `named_get`, `list`) call automatically feeds the `HealthMonitor`
//! classifier. Pre-fix, the classifier only fired when call sites
//! explicitly invoked `host.record_error(pid, &err)` — meaning a real
//! Discord auth-failure storm would never quarantine the provider
//! unless someone remembered to add the call. The Layer 2 baseline
//! test only worked because it poked the classifier directly.
//!
//! Architecture: `Host::register_chunk*` and `register_vault` wrap the
//! caller's plugin in `RecordingChunkPlugin` / `RecordingVaultPlugin`
//! before storing. Every call site that goes through `Host::get_chunk`
//! / `Host::get_vault` then records automatically. The `HealthMonitor`
//! is shared via `Arc` so multiple wrappers (per provider) all feed
//! the same classifier.

use std::sync::Arc;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::{BlakeHash, CasTier, ProviderId, Range};

use crate::contract::{
    CasResult, DeleteResult, HealthReport, ListEntry, PeekResult, PluginContract, PutResult,
    VaultPluginContract,
};
use crate::host::HealthMonitor;
use crate::rate_limit::RateLimitProfile;
use crate::Result;

/// Wraps a `PluginContract` so every put/get/peek/delete records to the
/// shared `HealthMonitor`. `health()` is left untouched — that one is
/// for the *plugin's self-reported* state and shouldn't fold into the
/// engine's classifier (the classifier is for "did the call succeed",
/// not "what does the backend say about itself").
pub struct RecordingChunkPlugin {
    inner: Arc<dyn PluginContract>,
    monitor: Arc<HealthMonitor>,
    provider_id: ProviderId,
}

impl RecordingChunkPlugin {
    pub fn new(
        inner: Arc<dyn PluginContract>,
        monitor: Arc<HealthMonitor>,
        provider_id: ProviderId,
    ) -> Self {
        Self {
            inner,
            monitor,
            provider_id,
        }
    }

    fn record_outcome<T>(&self, r: &Result<T>) {
        match r {
            Ok(_) => self.monitor.note_success(self.provider_id),
            Err(e) => self
                .monitor
                .record(self.provider_id, crate::host::classify_error(e)),
        }
    }
}

#[async_trait]
impl PluginContract for RecordingChunkPlugin {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult> {
        let r = self.inner.put(payload, hint).await;
        self.record_outcome(&r);
        r
    }
    async fn get(&self, handle: &NativeHandle, range: Option<Range>) -> Result<Vec<u8>> {
        let r = self.inner.get(handle, range).await;
        self.record_outcome(&r);
        r
    }
    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult> {
        let r = self.inner.peek(handle).await;
        self.record_outcome(&r);
        r
    }
    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult> {
        let r = self.inner.delete(handle).await;
        self.record_outcome(&r);
        r
    }
    async fn health(&self) -> Result<HealthReport> {
        // Don't fold the plugin's self-report into the classifier; the
        // classifier judges call outcomes only.
        self.inner.health().await
    }
    fn rate_limit_profile(&self) -> RateLimitProfile {
        self.inner.rate_limit_profile()
    }
}

/// Vault-role recording wrapper. Implements `VaultPluginContract` (which
/// extends `PluginContract`) so the same instance can be retrieved via
/// `Host::get_vault` and have its `cas_write` / `named_get` / `list`
/// calls recorded.
pub struct RecordingVaultPlugin {
    inner: Arc<dyn VaultPluginContract>,
    monitor: Arc<HealthMonitor>,
    provider_id: ProviderId,
}

impl RecordingVaultPlugin {
    pub fn new(
        inner: Arc<dyn VaultPluginContract>,
        monitor: Arc<HealthMonitor>,
        provider_id: ProviderId,
    ) -> Self {
        Self {
            inner,
            monitor,
            provider_id,
        }
    }

    fn record_outcome<T>(&self, r: &Result<T>) {
        match r {
            Ok(_) => self.monitor.note_success(self.provider_id),
            Err(e) => self
                .monitor
                .record(self.provider_id, crate::host::classify_error(e)),
        }
    }
}

#[async_trait]
impl PluginContract for RecordingVaultPlugin {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult> {
        let r = self.inner.put(payload, hint).await;
        self.record_outcome(&r);
        r
    }
    async fn get(&self, handle: &NativeHandle, range: Option<Range>) -> Result<Vec<u8>> {
        let r = self.inner.get(handle, range).await;
        self.record_outcome(&r);
        r
    }
    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult> {
        let r = self.inner.peek(handle).await;
        self.record_outcome(&r);
        r
    }
    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult> {
        let r = self.inner.delete(handle).await;
        self.record_outcome(&r);
        r
    }
    async fn health(&self) -> Result<HealthReport> {
        self.inner.health().await
    }
    fn rate_limit_profile(&self) -> RateLimitProfile {
        self.inner.rate_limit_profile()
    }
}

#[async_trait]
impl VaultPluginContract for RecordingVaultPlugin {
    async fn list(
        &self,
        prefix: &str,
        limit: u32,
        cursor: Option<Vec<u8>>,
    ) -> Result<(Vec<ListEntry>, Option<Vec<u8>>)> {
        let r = self.inner.list(prefix, limit, cursor).await;
        self.record_outcome(&r);
        r
    }
    async fn cas_write(
        &self,
        name: &str,
        payload: &[u8],
        expected_etag: Option<BlakeHash>,
    ) -> Result<CasResult> {
        let r = self.inner.cas_write(name, payload, expected_etag).await;
        self.record_outcome(&r);
        r
    }
    async fn named_get(
        &self,
        name: &str,
    ) -> Result<Option<(Vec<u8>, BlakeHash)>> {
        let r = self.inner.named_get(name).await;
        self.record_outcome(&r);
        r
    }
    fn cas_tier(&self) -> CasTier {
        self.inner.cas_tier()
    }
}

