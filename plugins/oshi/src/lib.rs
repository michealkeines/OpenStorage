//! `os-plugin-oshi` — `oshi.at`, anonymous large-file host with configurable
//! TTL and operator-issued admin URL.
//!
//! Endpoint: `PUT https://oshi.at/<name>` with raw body. Optional `Expire`
//! header (in minutes) overrides default retention. Response body looks
//! like:
//!
//! ```text
//! DL: https://oshi.at/AbCdEf/blob.bin
//! MANAGE: https://oshi.at/m/AbCdEf/<token>
//! ```
//!
//! We store the DL URL as the handle. The MANAGE URL is logged but not yet
//! used — wiring delete-via-manage is a follow-up; for now we surface
//! `DeleteOutcome::NotSupported` so the engine routes through the shadow
//! registry.
//!
//! Limits:
//! - ~5 GiB per file (operator-published; we cap at 1 GiB).
//! - Retention: configurable in minutes; default 90 days.
//! - No auth.
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
    http::{client::Body, HttpClient, HttpClientConfig, HttpRequest},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use reqwest::header::HeaderMap;
use reqwest::Method;

const BASE_URL: &str = "https://oshi.at";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_EXPIRY_MINUTES: u32 = 90 * 24 * 60;

#[derive(Debug, Clone)]
pub struct OshiPlugin {
    http: HttpClient,
    expiry_minutes: u32,
}

impl OshiPlugin {
    pub fn new() -> Self {
        Self::with_expiry(DEFAULT_EXPIRY_MINUTES)
    }

    pub fn with_expiry(expiry_minutes: u32) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-oshi/0.1".into(),
            ..Default::default()
        };
        Self {
            http: HttpClient::new(cfg),
            expiry_minutes,
        }
    }
}

impl Default for OshiPlugin {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_dl_url(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("DL:").map(|s| s.trim().to_string()))
        .filter(|u| u.starts_with("https://oshi.at/"))
}

#[async_trait]
impl PluginContract for OshiPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "oshi.at".into(),
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
                "payload {} exceeds oshi cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let url = format!("{BASE_URL}/blob.bin");
        let req = HttpRequest {
            method: Method::PUT,
            url,
            headers: HeaderMap::new(),
            body: Some(Body::Bytes(payload.to_vec())),
        }
        .header("Expire", &self.expiry_minutes.to_string());
        let resp = self.http.execute(req).await?;
        let body = std::str::from_utf8(&resp.body)
            .map_err(|_| PluginError::Plugin("non-utf8 response".into()))?;
        let dl = parse_dl_url(body)
            .ok_or_else(|| PluginError::Plugin(format!("could not parse DL from response: {body}")))?;
        Ok(PutResult {
            handle: NativeHandle(dl.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("oshi.at"),
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
                mtime: Timestamp::from_string("oshi.at"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("oshi.at"),
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
    fn parse_dl_typical() {
        let body = "DL: https://oshi.at/AbCdEf/blob.bin\nMANAGE: https://oshi.at/m/AbCdEf/tok\n";
        assert_eq!(
            parse_dl_url(body).as_deref(),
            Some("https://oshi.at/AbCdEf/blob.bin")
        );
    }

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = OshiPlugin::with_expiry(60);
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
