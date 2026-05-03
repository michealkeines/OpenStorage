//! `os-plugin-paste-rs` — `paste.rs`, a curl-friendly anonymous pastebin.
//!
//! - PUT/POST raw body, response is `https://paste.rs/<id>` (plain text).
//! - GET that URL → original bytes.
//! - No auth, no TTL hints (server keeps pastes "for a long time"; small
//!   pastes appear permanent).
//! - Service treats input as text. Binary needs base64 encoding to survive
//!   round-trip — we wrap on `put`, decode on `get`.
//!
//! Limits: ~10 MiB per paste (server-imposed), but practically much smaller
//! is recommended — large pastes are rejected with 413. We declare 64 KiB
//! to keep the engine's chunker reasonable.
//!
//! Privacy: ciphertext only.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    http::{client::Body, HttpClient, HttpClientConfig, HttpRequest},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};

const ENDPOINT: &str = "https://paste.rs/";
const MAX_OBJECT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct PasteRsPlugin {
    http: HttpClient,
}

impl PasteRsPlugin {
    pub fn new() -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-paste-rs/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
        }
    }
}

impl Default for PasteRsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluginContract for PasteRsPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "paste.rs".into(),
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
                "payload {} exceeds paste.rs cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let encoded = B64.encode(payload);
        let resp = self
            .http
            .execute(HttpRequest {
                method: reqwest::Method::POST,
                url: ENDPOINT.into(),
                headers: reqwest::header::HeaderMap::new(),
                body: Some(Body::Bytes(encoded.into_bytes())),
            })
            .await?;
        let url = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?
            .trim()
            .to_string();
        if !url.starts_with("https://paste.rs/") {
            return Err(PluginError::Plugin(format!("bad response: {url}")));
        }
        Ok(PutResult {
            handle: NativeHandle(url.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("paste.rs"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        _range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let url = std::str::from_utf8(&handle.0)
            .map_err(|_| PluginError::Plugin("invalid handle".into()))?;
        let bytes = self.http.get(url, None).await?;
        let s = std::str::from_utf8(&bytes)
            .map_err(|_| PluginError::Plugin("paste body not utf-8".into()))?
            .trim();
        B64.decode(s)
            .map_err(|e| PluginError::Plugin(format!("base64: {e}")))
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
                mtime: Timestamp::from_string("paste.rs"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("paste.rs"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
        // paste.rs has no DELETE for anonymous pastes.
        Ok(DeleteResult {
            outcome: DeleteOutcome::NotSupported,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::Medium,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(ENDPOINT).await {
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
        let p = PasteRsPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
