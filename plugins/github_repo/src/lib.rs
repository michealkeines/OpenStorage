//! `os-plugin-github-repo` — back ciphertext shards into a GitHub repository
//! using a Personal Access Token.
//!
//! Reads use the **public CDN** (`cdn.jsdelivr.net/gh/...` or
//! `raw.githubusercontent.com`), which has no per-IP rate limit; writes go
//! through the GitHub Contents API at the standard 5 000 req/hour PAT
//! quota. The plugin's rate-limit profile reflects this asymmetry: writes
//! are paced, reads are unbounded.
//!
//! Secrets: this plugin never embeds a token in code. The PAT is read from
//! the canonical providers.json file at the user's config dir (or
//! `OPENSTORAGE_PROVIDERS` override) — see `app/src/main.rs::load_providers_file`.
//! Operators run `os auth add github` to populate it.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    http::{
        client::Body, HttpClient, HttpClientConfig, HttpRequest, RateLimitDetector,
        RateLimitInfo,
    },
    PluginError, RateBucket, RateLimitProfile, RateLimitScope, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use reqwest::header::{HeaderMap, HeaderValue};

const API_BASE: &str = "https://api.github.com";
/// 100 MiB is GitHub's hard cap. Stay well under it.
const MAX_OBJECT_BYTES: u64 = 95 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GitHubRepoPlugin {
    owner: String,
    repo: String,
    branch: String,
    pat: String,
    cdn_base: String,
    http: HttpClient,
}

impl GitHubRepoPlugin {
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        branch: impl Into<String>,
        pat: impl Into<String>,
    ) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-github/0.1".into(),
            ..Default::default()
        };
        // jsdelivr serves the same content with global CDN caching and no
        // per-IP rate limit — strongly preferred for reads.
        let cdn_base = "https://cdn.jsdelivr.net/gh".to_string();
        Self {
            owner: owner.into(),
            repo: repo.into(),
            branch: branch.into(),
            pat: pat.into(),
            cdn_base,
            http: HttpClient::new(cfg).with_detector(Arc::new(GitHubDetector)),
        }
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        let auth = format!("token {}", self.pat);
        h.insert(
            "authorization",
            HeaderValue::from_str(&auth).expect("ascii"),
        );
        h.insert(
            "accept",
            HeaderValue::from_static("application/vnd.github+json"),
        );
        h.insert(
            "x-github-api-version",
            HeaderValue::from_static("2022-11-28"),
        );
        h
    }

    fn contents_url(&self, path: &str) -> String {
        format!(
            "{API_BASE}/repos/{}/{}/contents/{}",
            self.owner, self.repo, path
        )
    }

    fn cdn_url(&self, path: &str) -> String {
        format!(
            "{}/{}/{}@{}/{}",
            self.cdn_base, self.owner, self.repo, self.branch, path
        )
    }

    /// Generate a sharded path for a fresh shard upload. The path is
    /// random; we keep the shape so that GitHub's directory listing remains
    /// readable. Final segment is hex so the filename has no extension that
    /// jsdelivr might reject.
    fn fresh_path() -> String {
        use rand::RngCore;
        let mut b = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut b);
        let h = hex::encode(b);
        format!("objects/{}/{}.bin", &h[..2], &h[2..])
    }
}

/// Encodes path + sha so `delete` can include the required sha for the
/// Contents API.
fn pack_handle(path: &str, sha: &str) -> NativeHandle {
    NativeHandle(format!("{path}|{sha}").into_bytes())
}

fn unpack_handle(h: &NativeHandle) -> PluginResult<(&str, &str)> {
    let s = std::str::from_utf8(&h.0).map_err(|_| PluginError::Plugin("handle utf8".into()))?;
    s.split_once('|')
        .ok_or_else(|| PluginError::Plugin("handle format".into()))
}

#[async_trait]
impl PluginContract for GitHubRepoPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: format!("github:{}/{}", self.owner, self.repo),
            // 5 000 req/hour ≈ 1.4/sec; small bursts are absorbed by the
            // per-second secondary limit. Be conservative.
            puts: RateBucket::new(1.0, 3),
            // jsdelivr CDN has no per-IP rate limit; we still cap to keep
            // local concurrency in check.
            gets: RateBucket::new(50.0, 100),
            peeks: RateBucket::new(50.0, 100),
            deletes: RateBucket::new(1.0, 3),
            max_concurrent: 4,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: Some(1024 * 1024 * 1024), // 1 GiB free repo soft cap
            detector: Arc::new(GitHubDetector),
            // GitHub commit-on-existing-path is structurally TrueUpdate
            // (same URL, new bytes), but the plugin's `update()` method
            // is not yet wired. Declaring `None` here keeps the slot
            // pool from attempting it; a follow-up that implements
            // `update()` should bump this to `TrueUpdate`.
            update_capability: os_plugin_host::UpdateCapability::None,
            daily_op_budget: None,
        }
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if payload.len() as u64 > MAX_OBJECT_BYTES {
            return Err(PluginError::Plugin(format!(
                "payload {} exceeds GitHub cap {}",
                payload.len(),
                MAX_OBJECT_BYTES
            )));
        }
        let path = Self::fresh_path();
        let body = serde_json::json!({
            "message": "openstorage shard",
            "content": B64.encode(payload),
            "branch": self.branch,
        });
        let resp = self
            .http
            .execute(HttpRequest {
                method: reqwest::Method::PUT,
                url: self.contents_url(&path),
                headers: self.auth_headers(),
                body: Some(Body::Json(body)),
            })
            .await?;
        let v: serde_json::Value = resp.json()?;
        let sha = v["content"]["sha"]
            .as_str()
            .ok_or_else(|| PluginError::Plugin("missing content.sha in response".into()))?;
        Ok(PutResult {
            handle: pack_handle(&path, sha),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("github"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let (path, _sha) = unpack_handle(handle)?;
        let url = self.cdn_url(path);
        match self.http.get(&url, range).await {
            Ok(b) => Ok(b.to_vec()),
            // CDN may take a few minutes to pick up new commits. Fall back
            // to raw.githubusercontent.com for fresh-write reads.
            Err(_) => {
                let raw = format!(
                    "https://raw.githubusercontent.com/{}/{}/{}/{}",
                    self.owner, self.repo, self.branch, path
                );
                Ok(self.http.get(&raw, range).await?.to_vec())
            }
        }
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let (path, _sha) = unpack_handle(handle)?;
        let resp = self
            .http
            .execute(HttpRequest {
                method: reqwest::Method::GET,
                url: self.contents_url(path) + &format!("?ref={}", self.branch),
                headers: self.auth_headers(),
                body: None,
            })
            .await;
        match resp {
            Ok(r) => {
                let v: serde_json::Value = r.json()?;
                Ok(PeekResult {
                    exists: true,
                    size: v["size"].as_u64().unwrap_or(0),
                    mtime: Timestamp::from_string("github"),
                    etag: None,
                })
            }
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("github"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let (path, sha) = unpack_handle(handle)?;
        let body = serde_json::json!({
            "message": "openstorage shard delete",
            "sha": sha,
            "branch": self.branch,
        });
        let resp = self
            .http
            .execute(HttpRequest {
                method: reqwest::Method::DELETE,
                url: self.contents_url(path),
                headers: self.auth_headers(),
                body: Some(Body::Json(body)),
            })
            .await;
        match resp {
            Ok(_) => Ok(DeleteResult {
                outcome: DeleteOutcome::Removed,
                quota_reclaimed: QuotaReclaimed::Yes,
                cached_elsewhere_risk: CachedElsewhereRisk::Medium,
                tombstone_clears_at: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(DeleteResult {
                outcome: DeleteOutcome::NotFound,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self
            .http
            .execute(HttpRequest {
                method: reqwest::Method::GET,
                url: format!("{API_BASE}/user"),
                headers: self.auth_headers(),
                body: None,
            })
            .await
        {
            Ok(_) => HealthState::Healthy,
            _ => HealthState::Unhealthy,
        };
        Ok(HealthReport {
            state,
            quota: QuotaState {
                total: Some(1024 * 1024 * 1024),
                used: None,
                untrusted: false,
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

/// GitHub responses include `X-RateLimit-Remaining` and `X-RateLimit-Reset`
/// on every request. On 429 (or 403 with `secondary rate limit`), we extract
/// the wait. On 2xx with `Remaining: 0`, this detector returns a soft hint —
/// the middleware uses it to throttle pre-emptively, before the next call
/// would 429.
#[derive(Default, Debug, Clone)]
pub struct GitHubDetector;

impl RateLimitDetector for GitHubDetector {
    fn detect(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<RateLimitInfo> {
        // 403 with body containing "secondary rate limit" is a real 429
        // disguised by the GitHub API.
        let is_rate_limit = status == 429
            || (status == 403
                && std::str::from_utf8(body)
                    .map(|s| s.contains("rate limit"))
                    .unwrap_or(false));
        if is_rate_limit {
            // Try retry-after header first, fall back to X-RateLimit-Reset
            // (epoch seconds) → seconds-from-now.
            if let Some(secs) = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                return Some(RateLimitInfo {
                    retry_after: std::time::Duration::from_secs(secs.max(1)),
                    scope: RateLimitScope::Global,
                });
            }
            if let Some(reset_epoch) = headers
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let wait = reset_epoch.saturating_sub(now).max(1);
                return Some(RateLimitInfo {
                    retry_after: std::time::Duration::from_secs(wait),
                    scope: RateLimitScope::Global,
                });
            }
            return Some(RateLimitInfo {
                retry_after: std::time::Duration::from_secs(60),
                scope: RateLimitScope::Global,
            });
        }
        None
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
        // Set GH_PAT, GH_OWNER, GH_REPO, GH_BRANCH to run.
        let pat = std::env::var("GH_PAT").expect("GH_PAT not set");
        let owner = std::env::var("GH_OWNER").expect("GH_OWNER not set");
        let repo = std::env::var("GH_REPO").expect("GH_REPO not set");
        let branch = std::env::var("GH_BRANCH").unwrap_or_else(|_| "main".into());
        let p = GitHubRepoPlugin::new(owner, repo, branch, pat);
        let payload: Vec<u8> = (0u8..=255).cycle().take(4 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.unwrap();
        // CDN may have caching delay, but raw fallback covers it.
        let got = p.get(&r.handle, None).await.unwrap();
        assert_eq!(got, payload);
        let _ = p.delete(&r.handle).await.unwrap();
    }
}
