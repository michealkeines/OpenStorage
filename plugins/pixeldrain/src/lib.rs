//! `os-plugin-pixeldrain` — `pixeldrain.com`, large-file host with a
//! documented JSON API.
//!
//! Endpoint: `PUT https://pixeldrain.com/api/file/<name>` with the raw
//! body. Response is JSON `{"id":"...","name":"..."}`. The download URL is
//! `https://pixeldrain.com/api/file/<id>`.
//!
//! Anonymous mode in this plugin: no auth, no delete. With an API key the
//! same `id` can be deleted via `DELETE /api/file/<id>`; that's left for a
//! follow-up. We surface `DeleteOutcome::NotSupported` here so the engine
//! routes through the shadow registry.
//!
//! Limits:
//! - 20 GiB per file (operator-published; we cap at 1 GiB).
//! - Retention: ~30 days inactivity.
//! - Generous public quota; no published per-IP rate limit.
//!
//! Privacy: ciphertext only.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    http::{HttpClient, HttpClientConfig},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use serde::Deserialize;

const BASE_URL: &str = "https://pixeldrain.com";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PixeldrainPlugin {
    http: HttpClient,
}

impl PixeldrainPlugin {
    pub fn new() -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-pixeldrain/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
        }
    }
}

impl Default for PixeldrainPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct PutResp {
    id: String,
}

#[async_trait]
impl PluginContract for PixeldrainPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "pixeldrain.com".into(),
            puts: RateBucket::new(0.5, 2),
            gets: RateBucket::new(4.0, 8),
            peeks: RateBucket::new(4.0, 8),
            deletes: RateBucket::new(0.5, 1),
            max_concurrent: 2,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: None,
            detector: Arc::new(os_plugin_host::http::DefaultDetector),
            update_capability: os_plugin_host::UpdateCapability::None,
            daily_op_budget: None,
        }
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > MAX_OBJECT_BYTES {
            return Err(PluginError::Plugin(format!(
                "payload {} exceeds pixeldrain cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let url = format!("{BASE_URL}/api/file/blob.bin");
        let resp = self.http.put_bytes(&url, payload.to_vec()).await?;
        let parsed: PutResp = resp.json()?;
        if parsed.id.is_empty() {
            return Err(PluginError::Plugin("pixeldrain: empty id".into()));
        }
        let dl = format!("{BASE_URL}/api/file/{}", parsed.id);
        Ok(PutResult {
            handle: NativeHandle(dl.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("pixeldrain"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let url = std::str::from_utf8(&handle.0)
            .map_err(|_| PluginError::Plugin("invalid handle".into()))?;
        Ok(self.http.get(url, range).await?.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let url = std::str::from_utf8(&handle.0)
            .map_err(|_| PluginError::Plugin("invalid handle".into()))?;
        match self.http.head(url).await {
            Ok(resp) => Ok(PeekResult {
                exists: true,
                size: resp
                    .header_str("content-length")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                mtime: Timestamp::from_string("pixeldrain"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("pixeldrain"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
        Ok(DeleteResult {
            outcome: DeleteOutcome::NotSupported,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::Low,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(BASE_URL).await {
            Ok(_) => HealthState::Healthy,
            _ => HealthState::Unhealthy,
        };
        Ok(HealthReport {
            state,
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: true,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("n/a"),
            },
            latency: LatencyProfile::default(),
            score: if state == HealthState::Healthy {
                HealthScore::new(1.0)
            } else {
                HealthScore::new(0.0)
            },
        })
    }
}

#[allow(dead_code)]
fn _bind_etag(_: BlakeHash) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = PixeldrainPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
