//! `os-plugin-telegraph` — backend on top of Telegram's Telegraph publishing
//! platform (`telegra.ph`).
//!
//! Why this exists: Telegraph accepts **anonymous** account creation
//! (`createAccount` returns an `access_token` with no signup), and each
//! account can publish unlimited persistent pages of up to ~48 KB
//! base64-encoded payload each. That makes it a real "anywhere a string
//! lives" backend with no auth at all.
//!
//! - `put`     → POST `/createPage` (binary base64-encoded inside a `<pre>`
//!               node) → returns `path`. Handle = page path.
//! - `get`     → GET `/getPage/{path}?return_content=true`, extract the
//!               base64 from the first content node, decode.
//! - `peek`    → same getPage; existence + size derived from content length.
//! - `delete`  → Telegraph has no delete API; treat as Tombstoned, the
//!               engine registers a Shadow.
//!
//! Multi-instance: the natural unit is the `access_token`. Run the same
//! plugin code with N different tokens to get N independent providers,
//! each with its own rate-limit profile and quota. Token can be supplied
//! externally or fetched at construction via `from_anonymous()` which
//! creates a fresh anonymous account.
//!
//! Limits:
//!   - Page rendered HTML max ~64 KiB → payload ≈ 48 KiB after base64 expansion
//!   - No published per-account rate limit; we configure a conservative
//!     default in the profile (1 op/sec)
//!
//! Privacy: ciphertext only; the operator (Telegram LLC) sees opaque b64
//! pasted into a "pre" tag.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
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

const MAX_OBJECT_BYTES: u64 = 48 * 1024;
const API_BASE: &str = "https://api.telegra.ph";

#[derive(Debug, Clone)]
pub struct TelegraphPlugin {
    access_token: String,
    short_name: String,
    http: HttpClient,
}

impl TelegraphPlugin {
    pub fn new(access_token: impl Into<String>, short_name: impl Into<String>) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-telegraph/0.1".into(),
            ..Default::default()
        };
        Self {
            access_token: access_token.into(),
            short_name: short_name.into(),
            http: HttpClient::new(cfg),
        }
    }

    /// Mint a fresh anonymous Telegraph account and use its access_token.
    /// Useful for "spin up a new provider" without manual setup.
    pub async fn from_anonymous(short_name: impl Into<String>) -> PluginResult<Self> {
        let short_name = short_name.into();
        let cfg = HttpClientConfig {
            user_agent: "openstorage-telegraph/0.1".into(),
            ..Default::default()
        };
        let http = HttpClient::new(cfg);
        let resp = http
            .post_form(
                &format!("{API_BASE}/createAccount"),
                vec![
                    ("short_name".into(), short_name.clone()),
                    ("author_name".into(), "anon".into()),
                ],
            )
            .await?;
        let parsed: TgResp<AccountResult> = resp.json()?;
        if !parsed.ok || parsed.result.is_none() {
            return Err(PluginError::Plugin(
                parsed.error.unwrap_or_else(|| "createAccount failed".into()),
            ));
        }
        let token = parsed.result.unwrap().access_token;
        Ok(Self {
            access_token: token,
            short_name,
            http,
        })
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}

#[derive(Deserialize, Debug)]
struct TgResp<T> {
    ok: bool,
    #[serde(default, rename = "error")]
    error: Option<String>,
    result: Option<T>,
}

#[derive(Deserialize, Debug)]
struct AccountResult {
    access_token: String,
}

#[derive(Deserialize, Debug)]
struct PageResult {
    path: String,
    #[serde(default)]
    url: String,
}

#[derive(Deserialize, Debug)]
struct PageContentResult {
    #[serde(default)]
    content: Vec<serde_json::Value>,
}

#[async_trait]
impl PluginContract for TelegraphPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: format!("telegraph:{}", self.short_name),
            puts: RateBucket::new(1.0, 2),
            gets: RateBucket::new(4.0, 8),
            peeks: RateBucket::new(4.0, 8),
            deletes: RateBucket::new(1.0, 1),
            max_concurrent: 2,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: None,
            detector: std::sync::Arc::new(os_plugin_host::http::DefaultDetector),
        }
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > MAX_OBJECT_BYTES {
            return Err(PluginError::Plugin(format!(
                "payload {} exceeds Telegraph cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let encoded = B64.encode(payload);
        // Single <pre> node with the base64 string as its only child.
        let content = serde_json::json!([{
            "tag": "pre",
            "children": [encoded]
        }]);
        let resp = self
            .http
            .post_form(
                &format!("{API_BASE}/createPage"),
                vec![
                    ("access_token".into(), self.access_token.clone()),
                    ("title".into(), "blob".into()),
                    ("author_name".into(), "anon".into()),
                    ("content".into(), content.to_string()),
                    ("return_content".into(), "false".into()),
                ],
            )
            .await?;
        let parsed: TgResp<PageResult> = resp.json()?;
        if !parsed.ok || parsed.result.is_none() {
            return Err(PluginError::Plugin(
                parsed.error.unwrap_or_else(|| "createPage failed".into()),
            ));
        }
        let path = parsed.result.unwrap().path;
        Ok(PutResult {
            handle: NativeHandle(path.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("telegra.ph"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        _range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let path =
            std::str::from_utf8(&handle.0).map_err(|_| PluginError::Plugin("handle utf8".into()))?;
        let url = format!("{API_BASE}/getPage/{path}?return_content=true");
        let bytes = self.http.get(&url, None).await?;
        let parsed: TgResp<PageContentResult> =
            serde_json::from_slice(&bytes).map_err(|e| PluginError::Plugin(format!("json: {e}")))?;
        if !parsed.ok {
            return Err(PluginError::Plugin(
                parsed.error.unwrap_or_else(|| "getPage failed".into()),
            ));
        }
        let content = parsed
            .result
            .ok_or_else(|| PluginError::Plugin("missing result".into()))?
            .content;
        // First node should be the <pre> with our base64 child.
        let b64_str: &str = content
            .first()
            .and_then(|node| node.get("children"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|s| s.as_str())
            .ok_or_else(|| PluginError::Plugin("page content shape unexpected".into()))?;
        B64.decode(b64_str)
            .map_err(|e| PluginError::Plugin(format!("base64: {e}")))
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let path =
            std::str::from_utf8(&handle.0).map_err(|_| PluginError::Plugin("handle utf8".into()))?;
        let url = format!("{API_BASE}/getPage/{path}?return_content=false");
        match self.http.get(&url, None).await {
            Ok(_) => Ok(PeekResult {
                exists: true,
                size: 0,
                mtime: Timestamp::from_string("telegra.ph"),
                etag: None,
            }),
            Err(_) => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("telegra.ph"),
                etag: None,
            }),
        }
    }

    async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
        // Telegraph has no public delete endpoint. Pages are permanent. The
        // engine registers a Shadow with reason=DeletionOrphaned and the
        // residual report counts these.
        Ok(DeleteResult {
            outcome: DeleteOutcome::NotSupported,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::High,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.get(&format!("{API_BASE}/getAccountInfo?access_token={}", self.access_token), None).await {
            Ok(_) => HealthState::Healthy,
            Err(_) => HealthState::Unhealthy,
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
    async fn anonymous_round_trip() {
        let p = TelegraphPlugin::from_anonymous("os-test").await.unwrap();
        let payload: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
    }
}
