//! `os-plugin-x0clone` — parameterized 0x0-protocol plugin.
//!
//! 0x0 (originally `0x0.st`) is a small open-source upload server with
//! several independent public clones. They all share the same wire shape:
//!
//! - `POST {base}/` with multipart form, single field `file=@bytes`
//!   (no nested array; this differs from pomf-style hosts which use
//!   `files[]`).
//! - Response: plain-text body containing the resulting URL, often with a
//!   trailing newline.
//!
//! Verified live (current on the day this plugin shipped): `x0.at`.
//! Other historical operators (`0x0.st`, `envs.sh`) appear and disappear
//! periodically — register additional providers in `providers.json` when
//! you confirm an instance is up.
//!
//! Each instance is a distinct operator with its own retention, quota, and
//! egress IP — exactly what diversity wants. Register one provider per
//! instance:
//!
//! ```json
//! [
//!   {"kind":"x0","label":"x0.at",  "base":"https://x0.at",  "trust_group":"x0-x0at"},
//!   {"kind":"x0","label":"0x0.st", "base":"https://0x0.st", "trust_group":"x0-0x0st"}
//! ]
//! ```
//!
//! Privacy: ciphertext only. Deletion: 0x0 instances expose a "management
//! token" only via the `X-Token` response header at upload time; we don't
//! capture it in this batch, so `DeleteOutcome::NotSupported`. Retention is
//! a function of file size (smaller → longer; usually 30–365 days).

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
use reqwest::multipart;

const DEFAULT_MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct X0ClonePlugin {
    base: String,
    label: String,
    http: HttpClient,
    cap: u64,
}

impl X0ClonePlugin {
    /// `base` is the operator origin (e.g. `https://x0.at`). The plugin
    /// uploads to `{base}/` (the operator's root takes the multipart form).
    pub fn new(base: impl Into<String>, label: impl Into<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let label = label.into();
        let cfg = HttpClientConfig {
            user_agent: format!("openstorage-x0/0.1 ({label})"),
            ..Default::default()
        };
        Self {
            base,
            label,
            http: HttpClient::new(cfg),
            cap: DEFAULT_MAX_OBJECT_BYTES,
        }
    }

    pub fn with_max_object_bytes(mut self, cap: u64) -> Self {
        self.cap = cap;
        self
    }
}

fn first_url_token(body: &str, prefix_origin: &str) -> Option<String> {
    body.split_whitespace()
        .find(|tok| tok.starts_with(prefix_origin))
        .map(|s| s.to_string())
}

#[async_trait]
impl PluginContract for X0ClonePlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: format!("x0:{}", self.label),
            puts: RateBucket::new(0.5, 2),
            gets: RateBucket::new(4.0, 8),
            peeks: RateBucket::new(4.0, 8),
            deletes: RateBucket::new(0.5, 1),
            max_concurrent: 2,
            max_object_bytes: Some(self.cap),
            total_quota_bytes: None,
            detector: Arc::new(os_plugin_host::http::DefaultDetector),
            update_capability: os_plugin_host::UpdateCapability::None,
            daily_op_budget: None,
        }
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > self.cap {
            return Err(PluginError::Plugin(format!(
                "payload {} exceeds x0 cap {}",
                payload.len(),
                self.cap
            )));
        }
        let part = multipart::Part::bytes(payload.to_vec())
            .file_name("blob.bin")
            .mime_str("application/octet-stream")
            .map_err(|e| PluginError::Plugin(format!("multipart: {e}")))?;
        let form = multipart::Form::new().part("file", part);
        let upload_url = format!("{}/", self.base);
        let resp = self.http.post_multipart(&upload_url, form).await?;
        let body = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?;
        let url = first_url_token(body, &self.base)
            .ok_or_else(|| PluginError::Plugin(format!("x0 {}: bad response: {body}", self.label)))?;
        Ok(PutResult {
            handle: NativeHandle(url.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("x0"),
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
                mtime: Timestamp::from_string("x0"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("x0"),
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
        let state = match self.http.head(&self.base).await {
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
    fn parses_url_from_response_body() {
        let body = "https://x0.at/abc.bin\n";
        assert_eq!(
            first_url_token(body, "https://x0.at"),
            Some("https://x0.at/abc.bin".to_string())
        );
    }

    #[tokio::test]
    #[ignore]
    async fn live_round_trip_x0at() {
        let p = X0ClonePlugin::new("https://x0.at", "x0at");
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
