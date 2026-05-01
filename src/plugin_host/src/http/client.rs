//! `HttpClient` — the only path through which plugin HTTP traffic flows.
//!
//! Two guarantees:
//!
//! 1. Every non-2xx response is run through a `RateLimitDetector`. If the
//!    server told us to back off (header or body), the call returns
//!    `PluginError::RateLimited` — *not* `Unavailable`, *not* `Plugin`.
//! 2. Status-code mapping lives in `error::status_to_plugin_error` only.
//!    No plugin maintains its own status table.
//!
//! Plugins call `client.execute(...)` with a typed `HttpRequest`; everything
//! else (timeouts, multipart, retries, pacing) is provided by the host.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use os_types::Range;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    multipart, Method,
};

use crate::Result as PluginResult;

use super::error::status_to_plugin_error;
use super::ratelimit::{DefaultDetector, RateLimitDetector};

#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub user_agent: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub pool_idle_timeout: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            user_agent: "openstorage/0.1".into(),
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(180),
            pool_idle_timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    detector: Arc<dyn RateLimitDetector>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(cfg: HttpClientConfig) -> Self {
        let inner = reqwest::Client::builder()
            .user_agent(cfg.user_agent)
            .connect_timeout(cfg.connect_timeout)
            .timeout(cfg.request_timeout)
            .pool_idle_timeout(cfg.pool_idle_timeout)
            .build()
            .expect("reqwest builds");
        Self {
            inner,
            detector: Arc::new(DefaultDetector),
        }
    }

    /// Override the rate-limit detector. Use when the backend encodes 429s
    /// in JSON bodies (Telegram, Discord) instead of headers.
    pub fn with_detector(mut self, det: Arc<dyn RateLimitDetector>) -> Self {
        self.detector = det;
        self
    }

    pub fn detector(&self) -> &Arc<dyn RateLimitDetector> {
        &self.detector
    }

    /// Run an `HttpRequest` end-to-end. On 2xx returns the body. On any
    /// other status, the detector decides: if it identifies a rate-limit
    /// signal, the call returns `PluginError::RateLimited{retry_after}`;
    /// otherwise `status_to_plugin_error` maps to the right typed variant.
    pub async fn execute(&self, req: HttpRequest) -> PluginResult<HttpResponse> {
        let mut builder = self.inner.request(req.method, req.url.clone());
        for (k, v) in req.headers.iter() {
            builder = builder.header(k, v);
        }
        if let Some(body) = req.body {
            builder = match body {
                Body::Bytes(b) => builder.body(b),
                Body::Multipart(form) => builder.multipart(form),
                Body::Form(pairs) => builder.form(&pairs),
                Body::Json(v) => builder.json(&v),
            };
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| crate::PluginError::Io(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::PluginError::Io(e.to_string()))?;
        if (200..300).contains(&status) {
            return Ok(HttpResponse {
                status,
                headers,
                body: bytes,
            });
        }
        let rl = self.detector.detect(status, &headers, &bytes);
        Err(status_to_plugin_error(status, &bytes, rl))
    }

    // ─── ergonomic helpers ────────────────────────────────────────────────

    pub async fn get(&self, url: &str, range: Option<Range>) -> PluginResult<Bytes> {
        let mut headers = HeaderMap::new();
        if let Some(r) = range {
            let v = format!("bytes={}-{}", r.start, r.end.saturating_sub(1));
            headers.insert(
                "range",
                HeaderValue::from_str(&v).expect("ascii"),
            );
        }
        let resp = self
            .execute(HttpRequest {
                method: Method::GET,
                url: url.to_string(),
                headers,
                body: None,
            })
            .await?;
        Ok(resp.body)
    }

    pub async fn head(&self, url: &str) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::HEAD,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: None,
        })
        .await
    }

    pub async fn delete(&self, url: &str) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::DELETE,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: None,
        })
        .await
    }

    pub async fn post_multipart(
        &self,
        url: &str,
        form: multipart::Form,
    ) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::POST,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: Some(Body::Multipart(form)),
        })
        .await
    }

    pub async fn post_form(
        &self,
        url: &str,
        pairs: Vec<(String, String)>,
    ) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::POST,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: Some(Body::Form(pairs)),
        })
        .await
    }

    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        v: &T,
    ) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::POST,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: Some(Body::Json(serde_json::to_value(v).expect("serializable"))),
        })
        .await
    }

    pub async fn put_bytes(&self, url: &str, bytes: Vec<u8>) -> PluginResult<HttpResponse> {
        self.execute(HttpRequest {
            method: Method::PUT,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: Some(Body::Bytes(bytes)),
        })
        .await
    }
}

pub enum Body {
    Bytes(Vec<u8>),
    Multipart(multipart::Form),
    Form(Vec<(String, String)>),
    Json(serde_json::Value),
}

pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Option<Body>,
}

impl HttpRequest {
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.insert(
            HeaderName::from_bytes(k.as_bytes()).expect("ascii name"),
            HeaderValue::from_str(v).expect("ascii value"),
        );
        self
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> PluginResult<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| crate::PluginError::Plugin(format!("json: {e}")))
    }
}
