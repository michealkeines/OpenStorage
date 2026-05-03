//! `os-plugin-discord` — webhook backend.
//!
//! Routes all HTTP through `os_plugin_host::http::HttpClient` with a
//! `DiscordDetector` installed so 429 responses with the float
//! `retry_after` body field become `PluginError::RateLimited` automatically.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    http::{DiscordDetector, HttpClient, HttpClientConfig},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use reqwest::multipart;
use serde::Deserialize;

const MAX_OBJECT_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DiscordPlugin {
    webhook_url: String,
    http: HttpClient,
}

impl DiscordPlugin {
    pub fn new(webhook_url: impl Into<String>) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-discord/0.1".into(),
            ..Default::default()
        };
        Self {
            webhook_url: webhook_url.into().trim_end_matches('/').to_string(),
            http: HttpClient::new(cfg).with_detector(Arc::new(DiscordDetector)),
        }
    }

    pub fn from_env() -> Result<Self, &'static str> {
        let url = std::env::var("DISCORD_WEBHOOK_URL").map_err(|_| "DISCORD_WEBHOOK_URL not set")?;
        Ok(Self::new(url))
    }
}

#[derive(Deserialize, Debug)]
struct WebhookMessage {
    id: String,
    #[serde(default)]
    attachments: Vec<Attachment>,
}

#[derive(Deserialize, Debug)]
struct Attachment {
    url: String,
    #[allow(dead_code)]
    size: u64,
}

#[async_trait]
impl PluginContract for DiscordPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        // Discord webhooks: ~5 requests / 2 seconds per webhook bucket.
        RateLimitProfile {
            label: "discord-webhook".into(),
            puts: RateBucket::new(2.5, 5),
            gets: RateBucket::new(5.0, 10),
            peeks: RateBucket::new(5.0, 10),
            deletes: RateBucket::new(2.5, 5),
            max_concurrent: 5,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: None,
            detector: Arc::new(DiscordDetector),
            update_capability: os_plugin_host::UpdateCapability::None,
            daily_op_budget: None,
        }
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
        let form = multipart::Form::new().part("files[0]", part);
        let resp = self
            .http
            .post_multipart(&format!("{}?wait=true", self.webhook_url), form)
            .await?;
        let parsed: WebhookMessage = resp.json()?;
        let att = parsed
            .attachments
            .into_iter()
            .next()
            .ok_or_else(|| PluginError::Plugin("no attachment in response".into()))?;
        Ok(PutResult {
            handle: NativeHandle(format!("{}|{}", parsed.id, att.url).into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("discord"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let (_, url) = parse_handle(handle)?;
        Ok(self.http.get(url, range).await?.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let (_, url) = parse_handle(handle)?;
        match self.http.head(url).await {
            Ok(resp) => Ok(PeekResult {
                exists: true,
                size: resp
                    .header_str("content-length")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                mtime: Timestamp::from_string("discord"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("discord"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let (msg_id, _) = parse_handle(handle)?;
        let url = format!("{}/messages/{}", self.webhook_url, msg_id);
        match self.http.delete(&url).await {
            Ok(_) => Ok(DeleteResult {
                outcome: DeleteOutcome::Removed,
                quota_reclaimed: QuotaReclaimed::Yes,
                cached_elsewhere_risk: CachedElsewhereRisk::Medium,
                tombstone_clears_at: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(DeleteResult {
                outcome: DeleteOutcome::NotFound,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Medium,
                tombstone_clears_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(&self.webhook_url).await {
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

fn parse_handle(h: &NativeHandle) -> PluginResult<(&str, &str)> {
    let s = std::str::from_utf8(&h.0).map_err(|_| PluginError::Plugin("handle utf8".into()))?;
    s.split_once('|')
        .ok_or_else(|| PluginError::Plugin("handle format".into()))
}

#[allow(dead_code)]
fn _bind_etag(_: BlakeHash) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = DiscordPlugin::from_env().expect("env var");
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.expect("put");
        let got = p.get(&r.handle, None).await.expect("get");
        assert_eq!(got, payload);
        let _ = p.delete(&r.handle).await.expect("delete");
    }
}
