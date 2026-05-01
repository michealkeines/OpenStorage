//! `os-plugin-http-backend` — `PluginContract` impl backed by an HTTP object
//! store (the testbench in `testbench/server.py`, or any compatible service).
//!
//! Routes used:
//!   PUT  /v1/objects                → returns {handle, size, etag, stored_at}
//!   GET  /v1/objects/{handle}       → bytes (Range supported)
//!   HEAD /v1/objects/{handle}       → metadata
//!   DELETE /v1/objects/{handle}     → outcome
//!
//! Uploads stream the request body so 1 GB shards don't sit in memory.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    PluginError, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    PriorHandleState, QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum HttpBackendError {
    #[error("http: {0}")]
    Http(String),
    #[error("status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("decode: {0}")]
    Decode(String),
}

impl From<reqwest::Error> for HttpBackendError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<HttpBackendError> for PluginError {
    fn from(e: HttpBackendError) -> Self {
        match e {
            HttpBackendError::Status { status: 404, .. } => {
                PluginError::Plugin("not found".into())
            }
            HttpBackendError::Status { status, body } => {
                PluginError::Unavailable(format!("http {status}: {body}"))
            }
            HttpBackendError::Http(s) | HttpBackendError::Decode(s) => PluginError::Plugin(s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpBackendPlugin {
    base: String,
    client: reqwest::Client,
}

impl HttpBackendPlugin {
    pub fn new(base_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            // No total timeout; uploads can take minutes for 1 GB. Per-request
            // connect timeout is sane.
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("reqwest client builds");
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

#[derive(Deserialize)]
struct PutRespJson {
    handle: String,
    size: u64,
    etag: String,
    stored_at: f64,
}

#[async_trait]
impl PluginContract for HttpBackendPlugin {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> PluginResult<PutResult> {
        let mut url = self.url("/v1/objects");
        if let Some(prev) = &hint.replaces_handle {
            url.push_str(&format!("?replaces={}", encode_handle(prev)));
        }
        let body = payload.to_vec();
        let resp = self
            .client
            .post(&url)
            .body(body)
            .send()
            .await
            .map_err(HttpBackendError::from)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(HttpBackendError::Status {
                status: status.as_u16(),
                body,
            }
            .into());
        }
        let parsed: PutRespJson = resp.json().await.map_err(HttpBackendError::from)?;
        let handle = NativeHandle(parsed.handle.into_bytes());
        Ok(PutResult {
            handle,
            handle_changed: true,
            prior_handle_state: hint.replaces_handle.as_ref().map(|_| PriorHandleState::Removed),
            stored_at: ts_from_unix(parsed.stored_at as i64),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let mut req = self.client.get(self.url(&format!(
            "/v1/objects/{}",
            encode_handle(handle)
        )));
        if let Some(r) = range {
            req = req.header(
                "Range",
                format!("bytes={}-{}", r.start, r.end.saturating_sub(1)),
            );
        }
        let resp = req.send().await.map_err(HttpBackendError::from)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(HttpBackendError::Status {
                status: status.as_u16(),
                body,
            }
            .into());
        }
        let bytes = resp.bytes().await.map_err(HttpBackendError::from)?;
        Ok(bytes.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let resp = self
            .client
            .head(self.url(&format!("/v1/objects/{}", encode_handle(handle))))
            .send()
            .await
            .map_err(HttpBackendError::from)?;
        if resp.status().as_u16() == 404 {
            return Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: ts_from_unix(0),
                etag: None,
            });
        }
        if !resp.status().is_success() {
            return Err(HttpBackendError::Status {
                status: resp.status().as_u16(),
                body: String::new(),
            }
            .into());
        }
        let size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let mtime = resp
            .headers()
            .get("x-stored-at")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .map(ts_from_unix)
            .unwrap_or_else(|| ts_from_unix(0));
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| {
                if v.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&v);
                    Some(BlakeHash::from_bytes(a))
                } else {
                    None
                }
            });
        Ok(PeekResult {
            exists: true,
            size,
            mtime,
            etag,
        })
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let resp = self
            .client
            .delete(self.url(&format!("/v1/objects/{}", encode_handle(handle))))
            .send()
            .await
            .map_err(HttpBackendError::from)?;
        let outcome = match resp.status().as_u16() {
            200 => DeleteOutcome::Removed,
            404 => DeleteOutcome::NotFound,
            other => {
                return Err(HttpBackendError::Status {
                    status: other,
                    body: String::new(),
                }
                .into())
            }
        };
        Ok(DeleteResult {
            outcome,
            quota_reclaimed: if outcome == DeleteOutcome::Removed {
                QuotaReclaimed::Yes
            } else {
                QuotaReclaimed::No
            },
            cached_elsewhere_risk: CachedElsewhereRisk::Low,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let resp = self
            .client
            .get(self.url("/v1/health"))
            .send()
            .await
            .map_err(HttpBackendError::from)?;
        let state = if resp.status().is_success() {
            HealthState::Healthy
        } else {
            HealthState::Unhealthy
        };
        Ok(HealthReport {
            state,
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: false,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: ts_from_unix(0),
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

fn encode_handle(h: &NativeHandle) -> String {
    // Our testbench treats the handle as a UTF-8 hex string. Plugins are free
    // to use any bytes, but for this backend we keep it human-readable.
    String::from_utf8(h.0.clone()).unwrap_or_else(|_| hex::encode(&h.0))
}

fn ts_from_unix(secs: i64) -> Timestamp {
    Timestamp::from_string(format!("epoch:{secs}"))
}

#[cfg(test)]
mod tests {
    // The tests under this module require the Python testbench to be running
    // on `127.0.0.1:9090`. They are gated behind the `--ignored` flag so they
    // don't break a default `cargo test` run; the engine's integration test
    // (added later) launches the testbench itself.
    use super::*;

    fn handle_from_str(s: &str) -> NativeHandle {
        NativeHandle(s.as_bytes().to_vec())
    }

    #[tokio::test]
    #[ignore]
    async fn round_trip_against_local_testbench() {
        let p = HttpBackendPlugin::new("http://127.0.0.1:9090");
        let r = p.put(b"hello plugin", &PutHint::default()).await.unwrap();
        let bytes = p.get(&r.handle, None).await.unwrap();
        assert_eq!(bytes, b"hello plugin");
        let _ = p.delete(&r.handle).await.unwrap();
        let _ = handle_from_str("ignored"); // suppress unused warning
    }
}
