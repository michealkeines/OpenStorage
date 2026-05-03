//! `os-plugin-telegram` — Bot API backend.
//!
//! Routes all HTTP through `os_plugin_host::http::HttpClient` with a
//! `TelegramDetector` installed so 429s embedded in the JSON body
//! (`{"ok":false,"error_code":429,"parameters":{"retry_after":N}}`) become
//! `PluginError::RateLimited` automatically.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    http::{HttpClient, HttpClientConfig, TelegramDetector},
    PluginError, RateBucket, RateLimitProfile, Result as PluginResult,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};
use reqwest::multipart;
use serde::Deserialize;

const MAX_OBJECT_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct TelegramPlugin {
    bot_token: String,
    chat_id: String,
    http: HttpClient,
}

impl TelegramPlugin {
    pub fn new(bot_token: impl Into<String>, chat_id: impl Into<String>) -> Self {
        let cfg = HttpClientConfig {
            user_agent: "openstorage-telegram/0.1".into(),
            ..Default::default()
        };
        Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
            http: HttpClient::new(cfg).with_detector(Arc::new(TelegramDetector)),
        }
    }

    pub fn from_env() -> Result<Self, &'static str> {
        let token = std::env::var("TELEGRAM_BOT_TOKEN").map_err(|_| "TELEGRAM_BOT_TOKEN not set")?;
        let chat = std::env::var("TELEGRAM_CHAT_ID").map_err(|_| "TELEGRAM_CHAT_ID not set")?;
        Ok(Self::new(token, chat))
    }

    fn api(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    fn file_dl(&self, file_path: &str) -> String {
        format!(
            "https://api.telegram.org/file/bot{}/{}",
            self.bot_token, file_path
        )
    }
}

#[derive(Deserialize, Debug)]
struct TgResp<T> {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    result: Option<T>,
}

#[derive(Deserialize, Debug, Default)]
struct SendDocumentResult {
    message_id: i64,
    document: Option<TgDocument>,
}

#[derive(Deserialize, Debug, Default)]
struct TgDocument {
    file_id: String,
    #[allow(dead_code)]
    file_size: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
struct GetFileResult {
    file_path: String,
    file_size: Option<u64>,
}

#[async_trait]
impl PluginContract for TelegramPlugin {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        RateLimitProfile {
            label: "telegram-bot".into(),
            puts: RateBucket::new(1.0, 1),
            gets: RateBucket::new(4.0, 4),
            peeks: RateBucket::new(4.0, 4),
            deletes: RateBucket::new(1.0, 1),
            max_concurrent: 1,
            max_object_bytes: Some(MAX_OBJECT_BYTES),
            total_quota_bytes: None,
            detector: Arc::new(TelegramDetector),
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
        let form = multipart::Form::new()
            .text("chat_id", self.chat_id.clone())
            .part("document", part);
        let resp = self.http.post_multipart(&self.api("sendDocument"), form).await?;
        let parsed: TgResp<SendDocumentResult> = resp.json()?;
        if !parsed.ok || parsed.result.is_none() {
            return Err(PluginError::Plugin(
                parsed.description.unwrap_or_else(|| "telegram: unknown".into()),
            ));
        }
        let r = parsed.result.unwrap();
        let doc = r
            .document
            .ok_or_else(|| PluginError::Plugin("telegram: missing document".into()))?;
        let handle = NativeHandle(format!("{}|{}", doc.file_id, r.message_id).into_bytes());
        Ok(PutResult {
            handle,
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("telegram"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let (file_id, _) = parse_handle(handle)?;
        let resp = self
            .http
            .post_form(
                &self.api("getFile"),
                vec![("file_id".into(), file_id.into())],
            )
            .await?;
        let parsed: TgResp<GetFileResult> = resp.json()?;
        if !parsed.ok || parsed.result.is_none() {
            return Err(PluginError::Plugin(
                parsed.description.unwrap_or_else(|| "getFile failed".into()),
            ));
        }
        let path = parsed.result.unwrap().file_path;
        Ok(self.http.get(&self.file_dl(&path), range).await?.to_vec())
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let (file_id, _) = parse_handle(handle)?;
        let resp = self
            .http
            .post_form(
                &self.api("getFile"),
                vec![("file_id".into(), file_id.into())],
            )
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(_) => {
                return Ok(PeekResult {
                    exists: false,
                    size: 0,
                    mtime: Timestamp::from_string("telegram"),
                    etag: None,
                })
            }
        };
        let parsed: TgResp<GetFileResult> = resp.json()?;
        if !parsed.ok {
            return Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("telegram"),
                etag: None,
            });
        }
        Ok(PeekResult {
            exists: true,
            size: parsed.result.and_then(|r| r.file_size).unwrap_or(0),
            mtime: Timestamp::from_string("telegram"),
            etag: None,
        })
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let (_, message_id) = parse_handle(handle)?;
        if message_id == 0 {
            return Ok(DeleteResult {
                outcome: DeleteOutcome::NotSupported,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Medium,
                tombstone_clears_at: None,
            });
        }
        let resp = self
            .http
            .post_form(
                &self.api("deleteMessage"),
                vec![
                    ("chat_id".into(), self.chat_id.clone()),
                    ("message_id".into(), message_id.to_string()),
                ],
            )
            .await?;
        let parsed: TgResp<bool> = resp.json()?;
        let outcome = if parsed.ok && parsed.result.unwrap_or(false) {
            DeleteOutcome::Removed
        } else if parsed
            .description
            .as_deref()
            .map(|s| s.contains("not found"))
            .unwrap_or(false)
        {
            DeleteOutcome::NotFound
        } else {
            DeleteOutcome::Tombstoned
        };
        Ok(DeleteResult {
            outcome,
            quota_reclaimed: if outcome == DeleteOutcome::Removed {
                QuotaReclaimed::Yes
            } else {
                QuotaReclaimed::No
            },
            cached_elsewhere_risk: CachedElsewhereRisk::Medium,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        let state = match self.http.head(&self.api("getMe")).await {
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

fn parse_handle(h: &NativeHandle) -> PluginResult<(&str, i64)> {
    let s = std::str::from_utf8(&h.0).map_err(|_| PluginError::Plugin("handle utf8".into()))?;
    let (file_id, msg_str) = s
        .split_once('|')
        .ok_or_else(|| PluginError::Plugin("handle format".into()))?;
    let message_id = msg_str
        .parse::<i64>()
        .map_err(|_| PluginError::Plugin("handle msg id".into()))?;
    Ok((file_id, message_id))
}

#[allow(dead_code)]
fn _bind_etag(_: BlakeHash) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let p = TelegramPlugin::from_env().expect("env vars");
        let payload: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        let r = p.put(&payload, &PutHint::default()).await.expect("put");
        let got = p.get(&r.handle, None).await.expect("get");
        assert_eq!(got, payload);
        let _ = p.delete(&r.handle).await.expect("delete");
    }
}
