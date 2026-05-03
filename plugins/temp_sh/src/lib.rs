//! `os-plugin-temp-sh` — `temp.sh`, large-file curl-friendly host.
//!
//! Endpoint: `PUT https://temp.sh/upload/<name>` with raw body. Response
//! body is the plain-text URL `https://temp.sh/<id>/<name>`.
//!
//! Limits:
//! - 4 GiB per file (operator-published; we cap at 1 GiB to bound memory).
//! - 3-day retention, no auth.
//! - No deletion API. `DeleteOutcome::NotSupported`.
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

const BASE_URL: &str = "https://temp.sh";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct TempShPlugin {
    http: HttpClient,
}

impl TempShPlugin {
    pub fn new() -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-temp-sh/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
        }
    }
}

impl Default for TempShPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluginContract for TempShPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "temp.sh".into(),
            puts: RateBucket::new(0.5, 2),
            gets: RateBucket::new(2.0, 4),
            peeks: RateBucket::new(2.0, 4),
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
                "payload {} exceeds temp.sh cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let url = format!("{BASE_URL}/upload/blob.bin");
        let resp = self.http.put_bytes(&url, payload.to_vec()).await?;
        let body = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?
            .trim();
        // Response is sometimes the bare URL, sometimes a one-liner with
        // surrounding whitespace.
        let dl = body
            .split_whitespace()
            .find(|t| t.starts_with("https://temp.sh/"))
            .ok_or_else(|| PluginError::Plugin(format!("bad response: {body}")))?
            .to_string();
        Ok(PutResult {
            handle: NativeHandle(dl.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("temp.sh"),
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
                mtime: Timestamp::from_string("temp.sh"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("temp.sh"),
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
            Err(PluginError::Plugin(msg)) if msg.contains("405") => HealthState::Healthy,
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
        let p = TempShPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
