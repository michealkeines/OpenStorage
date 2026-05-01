//! `os-plugin-zeroxst` — anonymous public host (uguu.se).
//!
//! All HTTP traffic flows through `os_plugin_host::http::HttpClient`, which
//! parses `Retry-After` and emits `PluginError::RateLimited` automatically.
//! This plugin doesn't touch reqwest, status codes, or 429 logic directly.

#![forbid(unsafe_code)]

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
use reqwest::multipart;
use serde::Deserialize;

const UPLOAD_ENDPOINT: &str = "https://uguu.se/upload.php";
const MAX_OBJECT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ZeroxStPlugin {
    upload_url: String,
    http: HttpClient,
}

impl ZeroxStPlugin {
    pub fn new() -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-uguu/0.1".into(),
            ..Default::default()
        };
        Self {
            upload_url: UPLOAD_ENDPOINT.into(),
            http: HttpClient::new(cfg),
        }
    }
}

impl Default for ZeroxStPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct UguuResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    files: Vec<UguuFile>,
}

#[derive(Deserialize)]
struct UguuFile {
    url: String,
}

#[async_trait]
impl PluginContract for ZeroxStPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        // uguu.se has no published rate limit but is shared infrastructure;
        // be conservative — 1 op/sec, default Retry-After detector.
        RateLimitProfile::conservative("uguu-public")
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > MAX_OBJECT_BYTES {
            return Err(PluginError::Plugin(format!(
                "payload too large: {} bytes",
                payload.len()
            )));
        }
        let part = multipart::Part::bytes(payload.to_vec())
            .file_name("blob.bin")
            .mime_str("application/octet-stream")
            .map_err(|e| PluginError::Plugin(format!("multipart: {e}")))?;
        let form = multipart::Form::new().part("files[]", part);

        let resp = self.http.post_multipart(&self.upload_url, form).await?;
        let parsed: UguuResp = resp.json()?;
        if !parsed.success {
            return Err(PluginError::Plugin("uguu: success=false".into()));
        }
        let f = parsed
            .files
            .into_iter()
            .next()
            .ok_or_else(|| PluginError::Plugin("uguu: empty files[]".into()))?;
        Ok(PutResult {
            handle: NativeHandle(f.url.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("public-host"),
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
                mtime: Timestamp::from_string("public-host"),
                etag: None,
            }),
            Err(PluginError::Plugin(msg)) if msg.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("public-host"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
        // Uguu doesn't support deletion; the engine treats this as Tombstoned
        // and registers a Shadow with reason DeletionOrphaned.
        Ok(DeleteResult {
            outcome: DeleteOutcome::Tombstoned,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::Medium,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(&self.upload_url).await {
            Ok(_) => HealthState::Healthy,
            // 405 is fine — uguu doesn't allow HEAD on the upload endpoint.
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
        let p = ZeroxStPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
