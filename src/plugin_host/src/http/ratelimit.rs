//! Rate-limit detection — pluggable per backend.
//!
//! `RateLimitDetector::detect` is called by `HttpClient` after every
//! non-2xx response. It returns `Some(RateLimitInfo)` if the response is a
//! rate-limit signal — including the duration to wait. The default
//! detector handles the header-only case (`Retry-After`, plus the X-RateLimit-*
//! family). Backends that encode rate-limit info in the body install a
//! custom detector.

use std::time::Duration;

use crate::RateLimitScope;

#[derive(Debug, Clone, Copy)]
pub struct RateLimitInfo {
    pub retry_after: Duration,
    pub scope: RateLimitScope,
}

pub trait RateLimitDetector: Send + Sync {
    fn detect(&self, status: u16, headers: &reqwest::header::HeaderMap, body: &[u8])
        -> Option<RateLimitInfo>;
}

/// Default detector — header-only. Reads `Retry-After` (seconds) when status
/// is 429 or 503. Falls back to `X-RateLimit-Reset-After` (some Discord-ish
/// backends use this even on 200 + a remaining=0 hint, but we only react on
/// 429/503 to keep semantics clean).
#[derive(Default, Debug, Clone)]
pub struct DefaultDetector;

impl RateLimitDetector for DefaultDetector {
    fn detect(
        &self,
        status: u16,
        headers: &reqwest::header::HeaderMap,
        _body: &[u8],
    ) -> Option<RateLimitInfo> {
        if status != 429 && status != 503 {
            return None;
        }
        let secs = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .or_else(|| {
                headers
                    .get("x-ratelimit-reset-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<f64>().ok())
                    .map(|f| f.ceil() as u64)
            })
            .unwrap_or(1);
        Some(RateLimitInfo {
            retry_after: Duration::from_secs(secs.max(1)),
            scope: RateLimitScope::Global,
        })
    }
}

/// Telegram Bot API encodes 429 in the body:
/// `{"ok":false,"error_code":429,"description":"...","parameters":{"retry_after":N}}`.
/// We accept that *or* the plain HTTP-429 form.
#[derive(Default, Debug, Clone)]
pub struct TelegramDetector;

impl RateLimitDetector for TelegramDetector {
    fn detect(
        &self,
        status: u16,
        headers: &reqwest::header::HeaderMap,
        body: &[u8],
    ) -> Option<RateLimitInfo> {
        // Telegram sometimes returns HTTP 200 with a body containing
        // error_code 429, sometimes HTTP 429. Cover both.
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                if v.get("error_code").and_then(|x| x.as_i64()) == Some(429) {
                    let secs = v
                        .get("parameters")
                        .and_then(|p| p.get("retry_after"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(1);
                    return Some(RateLimitInfo {
                        retry_after: Duration::from_secs(secs.max(1)),
                        scope: RateLimitScope::Global,
                    });
                }
            }
        }
        DefaultDetector.detect(status, headers, body)
    }
}

/// Discord webhooks return HTTP 429 with a body
/// `{"message":"...","retry_after":<float seconds>,"global":<bool>}`.
#[derive(Default, Debug, Clone)]
pub struct DiscordDetector;

impl RateLimitDetector for DiscordDetector {
    fn detect(
        &self,
        status: u16,
        headers: &reqwest::header::HeaderMap,
        body: &[u8],
    ) -> Option<RateLimitInfo> {
        if status == 429 {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                let retry = v.get("retry_after").and_then(|x| x.as_f64()).unwrap_or(1.0);
                let global = v.get("global").and_then(|x| x.as_bool()).unwrap_or(false);
                let ms = (retry * 1000.0).max(100.0) as u64;
                return Some(RateLimitInfo {
                    retry_after: Duration::from_millis(ms),
                    scope: if global {
                        RateLimitScope::Global
                    } else {
                        RateLimitScope::Bucket
                    },
                });
            }
        }
        DefaultDetector.detect(status, headers, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    fn hdr(k: &str, v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
        h
    }

    #[test]
    fn default_reads_retry_after_header() {
        let info = DefaultDetector.detect(429, &hdr("retry-after", "30"), b"").unwrap();
        assert_eq!(info.retry_after, Duration::from_secs(30));
        assert_eq!(info.scope, RateLimitScope::Global);
    }

    #[test]
    fn default_falls_back_to_x_ratelimit() {
        let info = DefaultDetector
            .detect(429, &hdr("x-ratelimit-reset-after", "12.7"), b"")
            .unwrap();
        assert_eq!(info.retry_after, Duration::from_secs(13));
    }

    #[test]
    fn default_ignores_non_rate_limit_codes() {
        assert!(DefaultDetector.detect(404, &HeaderMap::new(), b"").is_none());
        assert!(DefaultDetector.detect(500, &HeaderMap::new(), b"").is_none());
    }

    #[test]
    fn telegram_reads_body_retry_after() {
        let body = br#"{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":17}}"#;
        let info = TelegramDetector.detect(200, &HeaderMap::new(), body).unwrap();
        assert_eq!(info.retry_after, Duration::from_secs(17));
    }

    #[test]
    fn telegram_falls_back_to_header() {
        let info = TelegramDetector
            .detect(429, &hdr("retry-after", "5"), b"{}")
            .unwrap();
        assert_eq!(info.retry_after, Duration::from_secs(5));
    }

    #[test]
    fn discord_reads_body_retry_after_float() {
        let info = DiscordDetector
            .detect(
                429,
                &HeaderMap::new(),
                br#"{"message":"You are being rate limited.","retry_after":0.45,"global":true}"#,
            )
            .unwrap();
        assert_eq!(info.retry_after, Duration::from_millis(450));
        assert_eq!(info.scope, RateLimitScope::Global);
    }

    #[test]
    fn discord_distinguishes_bucket_scope() {
        let info = DiscordDetector
            .detect(
                429,
                &HeaderMap::new(),
                br#"{"retry_after":1.0,"global":false}"#,
            )
            .unwrap();
        assert_eq!(info.scope, RateLimitScope::Bucket);
    }
}
