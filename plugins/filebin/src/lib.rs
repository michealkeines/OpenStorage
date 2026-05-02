//! `os-plugin-filebin` — `filebin.net`, anonymous bin-based file host.
//!
//! Endpoint: PUT `https://filebin.net/{bin}/{filename}` with raw bytes;
//! GET / DELETE the same URL. The bin is a client-chosen string; we use a
//! UUIDv7 per plugin instance so each provider config owns one private bin.
//!
//! Limits (operator-published):
//! - 5 GiB per bin total
//! - Files in a bin expire 7 days after the bin's first upload (whole bin
//!   wiped). Engine treats expired handles as `Tombstoned` via Shadow.
//! - No public per-IP rate limit; we configure conservative defaults.
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
    http::{Body, HttpClient, HttpClientConfig, HttpRequest},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use reqwest::Method;
use os_types::{
    CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile, QuotaReclaimed,
    QuotaState, Range, RateLimitState, Timestamp,
};
use uuid::Uuid;

const BASE: &str = "https://filebin.net";
const MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FilebinPlugin {
    http: HttpClient,
    bin: String,
}

impl FilebinPlugin {
    pub fn new() -> Self {
        Self::with_bin(format!("os-{}", Uuid::now_v7().simple()))
    }

    pub fn with_bin(bin: String) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-filebin/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
            bin,
        }
    }

    pub fn bin(&self) -> &str {
        &self.bin
    }

    fn url_for(&self, name: &str) -> String {
        format!("{}/{}/{}", BASE, self.bin, name)
    }

    fn parse_handle<'a>(h: &'a NativeHandle) -> PluginResult<(&'a str, &'a str)> {
        let s = std::str::from_utf8(&h.0)
            .map_err(|_| PluginError::Plugin("invalid handle: non-utf8".into()))?;
        let (bin, name) = s
            .split_once('/')
            .ok_or_else(|| PluginError::Plugin("invalid handle: missing '/'".into()))?;
        Ok((bin, name))
    }
}

impl Default for FilebinPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluginContract for FilebinPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: format!("filebin:{}", self.bin),
            puts: RateBucket::new(0.5, 2),
            gets: RateBucket::new(4.0, 8),
            peeks: RateBucket::new(4.0, 8),
            deletes: RateBucket::new(0.5, 1),
            max_concurrent: 2,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: Some(MAX_OBJECT_BYTES),
            detector: Arc::new(os_plugin_host::http::DefaultDetector),
        }
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > MAX_OBJECT_BYTES {
            return Err(PluginError::Plugin(format!(
                "payload {} exceeds filebin cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let name = format!("{}.bin", Uuid::now_v7().simple());
        let url = self.url_for(&name);
        let req = HttpRequest {
            method: Method::PUT,
            url,
            headers: Default::default(),
            body: Some(Body::Bytes(payload.to_vec())),
        }
        .header("Content-Type", "application/octet-stream");
        let _ = self.http.execute(req).await?;
        let handle = format!("{}/{}", self.bin, name);
        Ok(PutResult {
            handle: NativeHandle(handle.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("filebin"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        _range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let (bin, name) = Self::parse_handle(handle)?;
        // filebin gates direct downloads behind a `verified` cookie that is
        // set on first visit (HTML interstitial). We skip the interstitial
        // by always sending the cookie; without it, the URL returns HTML.
        let url = format!("{}/{}/{}", BASE, bin, name);
        let req = HttpRequest {
            method: Method::GET,
            url,
            headers: Default::default(),
            body: None,
        }
        .header("Cookie", "verified=2024-05-24");
        Ok(self.http.execute(req).await?.body.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let (bin, name) = Self::parse_handle(handle)?;
        let url = format!("{}/{}/{}", BASE, bin, name);
        let req = HttpRequest {
            method: Method::HEAD,
            url,
            headers: Default::default(),
            body: None,
        }
        .header("Cookie", "verified=2024-05-24");
        match self.http.execute(req).await {
            Ok(resp) => Ok(PeekResult {
                exists: true,
                size: resp
                    .header_str("content-length")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                mtime: Timestamp::from_string("filebin"),
                etag: None,
            }),
            Err(PluginError::NotFound(_)) => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("filebin"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let (bin, name) = Self::parse_handle(handle)?;
        let url = format!("{}/{}/{}", BASE, bin, name);
        match self.http.delete(&url).await {
            Ok(_) => Ok(DeleteResult {
                outcome: DeleteOutcome::Removed,
                quota_reclaimed: QuotaReclaimed::Yes,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            }),
            Err(PluginError::NotFound(_)) => Ok(DeleteResult {
                outcome: DeleteOutcome::NotFound,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(BASE).await {
            Ok(_) => HealthState::Healthy,
            _ => HealthState::Unhealthy,
        };
        Ok(HealthReport {
            state,
            quota: QuotaState {
                total: Some(MAX_OBJECT_BYTES),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = FilebinPlugin::new();
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
        let _ = p.delete(&r.handle).await.unwrap();
    }
}
