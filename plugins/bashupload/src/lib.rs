//! `os-plugin-bashupload` — `bashupload.com`, `curl -T file bashupload.com`.
//!
//! Endpoint: `PUT https://bashupload.com/<name>` with the raw payload as
//! body. Response body is plain text containing a `wget <url>` line; we
//! parse out the URL.
//!
//! Limits:
//! - 50 GiB per file (operator-published; we cap at 1 GiB to keep memory
//!   bounded for the engine's chunk path).
//! - 3-day retention, no auth.
//! - No deletion API. `DeleteOutcome::NotSupported` → engine registers a
//!   Shadow until the 3-day TTL elapses.
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

const BASE_URL: &str = "https://bashupload.com";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BashuploadPlugin {
    http: HttpClient,
}

impl BashuploadPlugin {
    pub fn new() -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-bashupload/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
        }
    }
}

impl Default for BashuploadPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Pull the first https://bashupload.com/... token out of a response body.
fn extract_url(body: &str) -> Option<String> {
    body.split_whitespace()
        .find(|tok| tok.starts_with("https://bashupload.com/"))
        .map(|s| s.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '/' && c != '.' && c != '-' && c != '_').to_string())
}

#[async_trait]
impl PluginContract for BashuploadPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "bashupload.com".into(),
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
                "payload {} exceeds bashupload cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        // Stable but unique target name; bashupload returns a fresh path
        // segment regardless, but we still pass a sensible filename.
        let url = format!("{BASE_URL}/blob.bin");
        let resp = self.http.put_bytes(&url, payload.to_vec()).await?;
        let body = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?;
        let download = extract_url(body)
            .ok_or_else(|| PluginError::Plugin(format!("could not parse URL from response: {body}")))?;
        Ok(PutResult {
            handle: NativeHandle(download.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("bashupload"),
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
        // bashupload appends ?download=1 for raw bytes; otherwise it serves
        // a small HTML preview for browsers.
        let raw_url = if url.contains('?') {
            url.to_string()
        } else {
            format!("{url}?download=1")
        };
        Ok(self.http.get(&raw_url, range).await?.to_vec())
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
                mtime: Timestamp::from_string("bashupload"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("bashupload"),
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

    #[test]
    fn parse_url_from_typical_response() {
        let body = "Uploaded 1 file, 4096 bytes\n\nwget https://bashupload.com/Ax9/blob.bin\n";
        assert_eq!(
            extract_url(body).as_deref(),
            Some("https://bashupload.com/Ax9/blob.bin")
        );
    }

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = BashuploadPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
