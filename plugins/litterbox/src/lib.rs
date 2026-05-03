//! `os-plugin-litterbox` — `litterbox.catbox.moe`, the ephemeral sister of
//! catbox. Same operator, same wire shape, but every upload has a TTL of
//! 1h / 12h / 24h / 72h chosen at upload time.
//!
//! Endpoint: POST `https://litterbox.catbox.moe/resources/internals/api.php`
//! with multipart form `reqtype=fileupload`, `time=<bucket>`,
//! `fileToUpload=@bytes`. Response is the file URL in plain text.
//!
//! Limits:
//! - 1 GiB per file (operator-published)
//! - TTL fixed per provider instance (default 72h)
//! - No published per-IP rate limit; conservative profile applied.
//! - No deletion API (TTL handles it). `DeleteOutcome::NotSupported`,
//!   engine registers a Shadow with reason `DeletionOrphaned` until the
//!   tombstone clears at the known TTL.
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
use reqwest::multipart;

const UPLOAD_ENDPOINT: &str =
    "https://litterbox.catbox.moe/resources/internals/api.php";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Permitted TTL buckets accepted by the operator.
#[derive(Debug, Clone, Copy)]
pub enum LitterboxTtl {
    OneHour,
    TwelveHours,
    OneDay,
    ThreeDays,
}

impl LitterboxTtl {
    fn as_str(self) -> &'static str {
        match self {
            LitterboxTtl::OneHour => "1h",
            LitterboxTtl::TwelveHours => "12h",
            LitterboxTtl::OneDay => "24h",
            LitterboxTtl::ThreeDays => "72h",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LitterboxPlugin {
    http: HttpClient,
    ttl: LitterboxTtl,
}

impl LitterboxPlugin {
    pub fn new() -> Self {
        Self::with_ttl(LitterboxTtl::ThreeDays)
    }

    pub fn with_ttl(ttl: LitterboxTtl) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-litterbox/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
            ttl,
        }
    }
}

impl Default for LitterboxPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluginContract for LitterboxPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "litterbox.catbox.moe".into(),
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
                "payload {} exceeds litterbox cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let part = multipart::Part::bytes(payload.to_vec())
            .file_name("blob.bin")
            .mime_str("application/octet-stream")
            .map_err(|e| PluginError::Plugin(format!("multipart: {e}")))?;
        let form = multipart::Form::new()
            .text("reqtype", "fileupload")
            .text("time", self.ttl.as_str())
            .part("fileToUpload", part);
        let resp = self.http.post_multipart(UPLOAD_ENDPOINT, form).await?;
        let url = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?
            .trim()
            .to_string();
        if !url.starts_with("https://litter.catbox.moe/")
            && !url.starts_with("https://litterbox.catbox.moe/")
        {
            return Err(PluginError::Plugin(format!("bad response: {url}")));
        }
        Ok(PutResult {
            handle: NativeHandle(url.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("litterbox"),
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
                mtime: Timestamp::from_string("litterbox"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("litterbox"),
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
        let state = match self.http.head("https://litterbox.catbox.moe/").await {
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
        let p = LitterboxPlugin::with_ttl(LitterboxTtl::OneHour);
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
