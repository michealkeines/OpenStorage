//! `os-plugin-http-backend` — talks to the Python testbench (or any
//! compatible HTTP object store).
//!
//! Both the chunk-role (`PluginContract`) and vault-role
//! (`VaultPluginContract`) implementations route HTTP through
//! `os_plugin_host::http::HttpClient`. The default `RateLimitDetector` is
//! enough — the testbench, like most HTTP object stores, signals 429 via
//! the `Retry-After` header.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        CasOutcome, CasResult, DeleteResult, HealthReport, HealthState, ListEntry, PeekResult,
        PluginContract, PutResult, VaultPluginContract,
    },
    http::{HttpClient, HttpClientConfig},
    PluginError, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct HttpBackendPlugin {
    base: String,
    http: HttpClient,
}

impl HttpBackendPlugin {
    pub fn new(base_url: impl Into<String>) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-http-backend/0.1".into(),
            ..Default::default()
        };
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: HttpClient::new(cfg),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

#[derive(Deserialize)]
struct PutRespJson {
    handle: String,
    #[allow(dead_code)]
    size: u64,
    #[allow(dead_code)]
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
        let resp = self
            .http
            .execute(os_plugin_host::http::HttpRequest {
                method: reqwest::Method::POST,
                url,
                headers: reqwest::header::HeaderMap::new(),
                body: Some(os_plugin_host::http::client::Body::Bytes(payload.to_vec())),
            })
            .await?;
        let parsed: PutRespJson = resp.json()?;
        Ok(PutResult {
            handle: NativeHandle(parsed.handle.into_bytes()),
            handle_changed: true,
            prior_handle_state: hint
                .replaces_handle
                .as_ref()
                .map(|_| os_types::PriorHandleState::Removed),
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
        let url = self.url(&format!("/v1/objects/{}", encode_handle(handle)));
        Ok(self.http.get(&url, range).await?.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let url = self.url(&format!("/v1/objects/{}", encode_handle(handle)));
        match self.http.head(&url).await {
            Ok(resp) => {
                let size = resp
                    .header_str("content-length")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let mtime = resp
                    .header_str("x-stored-at")
                    .and_then(|s| s.parse().ok())
                    .map(ts_from_unix)
                    .unwrap_or_else(|| ts_from_unix(0));
                let etag = resp
                    .header_str("etag")
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
            Err(PluginError::Plugin(msg)) if msg.contains("not found") => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: ts_from_unix(0),
                etag: None,
            }),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let url = self.url(&format!("/v1/objects/{}", encode_handle(handle)));
        match self.http.delete(&url).await {
            Ok(_) => Ok(DeleteResult {
                outcome: DeleteOutcome::Removed,
                quota_reclaimed: QuotaReclaimed::Yes,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
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
        let state = match self.http.execute(os_plugin_host::http::HttpRequest {
            method: reqwest::Method::GET,
            url: self.url("/v1/health"),
            headers: reqwest::header::HeaderMap::new(),
            body: None,
        }).await {
            Ok(_) => HealthState::Healthy,
            _ => HealthState::Unhealthy,
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

#[async_trait]
impl VaultPluginContract for HttpBackendPlugin {
    async fn list(
        &self,
        prefix: &str,
        limit: u32,
        cursor: Option<Vec<u8>>,
    ) -> PluginResult<(Vec<ListEntry>, Option<Vec<u8>>)> {
        let mut url = self.url(&format!("/v1/named?prefix={prefix}&limit={limit}"));
        if let Some(c) = &cursor {
            url.push_str("&cursor=");
            url.push_str(&urlencode(std::str::from_utf8(c).unwrap_or_default()));
        }
        let resp = self
            .http
            .execute(os_plugin_host::http::HttpRequest {
                method: reqwest::Method::GET,
                url,
                headers: reqwest::header::HeaderMap::new(),
                body: None,
            })
            .await?;
        let parsed: serde_json::Value = resp.json()?;
        let mut entries = Vec::new();
        if let Some(arr) = parsed["entries"].as_array() {
            for e in arr {
                let name = e["name"].as_str().unwrap_or_default().to_string();
                let size = e["size"].as_u64().unwrap_or(0);
                let etag = e["etag"]
                    .as_str()
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
                let mtime = e["mtime"]
                    .as_i64()
                    .map(ts_from_unix)
                    .unwrap_or_else(|| ts_from_unix(0));
                entries.push(ListEntry {
                    name,
                    size,
                    etag,
                    mtime,
                });
            }
        }
        let next_cursor = parsed["next_cursor"]
            .as_str()
            .map(|s| s.as_bytes().to_vec());
        Ok((entries, next_cursor))
    }

    async fn cas_write(
        &self,
        name: &str,
        payload: &[u8],
        expected_etag: Option<BlakeHash>,
    ) -> PluginResult<CasResult> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(et) = expected_etag {
            headers.insert(
                "if-match",
                reqwest::header::HeaderValue::from_str(&hex::encode(et.as_bytes())).unwrap(),
            );
        }
        let url = self.url(&format!("/v1/named/{}", urlencode(name)));
        let resp = self
            .http
            .execute(os_plugin_host::http::HttpRequest {
                method: reqwest::Method::PUT,
                url,
                headers,
                body: Some(os_plugin_host::http::client::Body::Bytes(payload.to_vec())),
            })
            .await;
        match resp {
            Ok(r) => {
                let body: serde_json::Value = r.json()?;
                let new_etag = body["new_etag"]
                    .as_str()
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
                Ok(CasResult {
                    outcome: CasOutcome::Written,
                    new_etag,
                })
            }
            Err(PluginError::Plugin(m)) if m.contains("client error 412") => Ok(CasResult {
                outcome: CasOutcome::EtagMismatch,
                new_etag: None,
            }),
            Err(e) => Err(e),
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*b as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

fn encode_handle(h: &NativeHandle) -> String {
    String::from_utf8(h.0.clone()).unwrap_or_else(|_| hex::encode(&h.0))
}

fn ts_from_unix(secs: i64) -> Timestamp {
    Timestamp::from_string(format!("epoch:{secs}"))
}

#[cfg(test)]
mod tests {
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
        let _ = handle_from_str("ignored");
    }
}
