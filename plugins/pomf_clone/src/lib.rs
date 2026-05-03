//! `os-plugin-pomf-clone` — parameterized plugin for any pomf-protocol host.
//!
//! Pomf is a small open-source upload server with many independent public
//! deployments. They all share the same wire shape:
//!
//! - `POST {base}/upload.php` (sometimes `{base}/upload`) with multipart
//!   form, field name `files[]`. The form may include any number of files;
//!   we always send one.
//! - Response: JSON `{"success":true,"files":[{"url":"...","hash":"...",
//!   "size":N}]}`.
//!
//! Each instance is a distinct operator with its own retention, quota, and
//! egress IP — exactly what you want for trust-group diversity. Register
//! one provider per instance in `providers.json`:
//!
//! ```json
//! [
//!   {"kind":"pomf","label":"lain","base":"https://pomf.lain.la","trust_group":"pomf-lain"},
//!   {"kind":"pomf","label":"safe","base":"https://safe.fiery.me","trust_group":"pomf-safe"},
//!   {"kind":"pomf","label":"kek","base":"https://kek.sh","upload_path":"/upload","trust_group":"pomf-kek"}
//! ]
//! ```
//!
//! Privacy: ciphertext only. Deletion: not exposed by the public pomf API,
//! so `DeleteOutcome::NotSupported`.

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
use serde::Deserialize;

const DEFAULT_UPLOAD_PATH: &str = "/upload.php";
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PomfClonePlugin {
    base: String,
    upload_url: String,
    label: String,
    http: HttpClient,
    cap: u64,
}

impl PomfClonePlugin {
    /// `base` is the operator origin (e.g. `https://pomf.lain.la`).
    /// `upload_path` defaults to `/upload.php` if `None`.
    pub fn new(base: impl Into<String>, upload_path: Option<&str>, label: impl Into<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let upload_url = format!("{base}{}", upload_path.unwrap_or(DEFAULT_UPLOAD_PATH));
        let label = label.into();
        let cfg = HttpClientConfig {
            user_agent: format!("openstorage-pomf/0.1 ({label})"),
            ..Default::default()
        };
        Self {
            base,
            upload_url,
            label,
            http: HttpClient::new(cfg),
            cap: MAX_OBJECT_BYTES,
        }
    }

    pub fn with_max_object_bytes(mut self, cap: u64) -> Self {
        self.cap = cap;
        self
    }
}

#[derive(Deserialize)]
struct PomfResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    files: Vec<PomfFile>,
}

#[derive(Deserialize)]
struct PomfFile {
    url: String,
}

#[async_trait]
impl PluginContract for PomfClonePlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: format!("pomf:{}", self.label),
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
                "payload {} exceeds pomf cap {}",
                payload.len(),
                self.cap
            )));
        }
        let part = multipart::Part::bytes(payload.to_vec())
            .file_name("blob.bin")
            .mime_str("application/octet-stream")
            .map_err(|e| PluginError::Plugin(format!("multipart: {e}")))?;
        let form = multipart::Form::new().part("files[]", part);
        let resp = self.http.post_multipart(&self.upload_url, form).await?;
        let parsed: PomfResp = resp.json()?;
        if !parsed.success {
            return Err(PluginError::Plugin(format!(
                "pomf {}: success=false",
                self.label
            )));
        }
        let f = parsed
            .files
            .into_iter()
            .next()
            .ok_or_else(|| PluginError::Plugin(format!("pomf {}: empty files[]", self.label)))?;
        Ok(PutResult {
            handle: NativeHandle(f.url.into_bytes()),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("pomf"),
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
                mtime: Timestamp::from_string("pomf"),
                etag: None,
            }),
            Err(PluginError::Plugin(m)) if m.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("pomf"),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
        Ok(DeleteResult {
            outcome: DeleteOutcome::NotSupported,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::Medium,
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
    fn upload_url_is_assembled_from_base_and_path() {
        let p = PomfClonePlugin::new("https://pomf.lain.la", None, "lain");
        assert_eq!(p.upload_url, "https://pomf.lain.la/upload.php");
        let p = PomfClonePlugin::new("https://kek.sh/", Some("/upload"), "kek");
        assert_eq!(p.upload_url, "https://kek.sh/upload");
    }
}
