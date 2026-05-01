//! Rate-limit middleware — a host-level decorator over `PluginContract`.
//!
//! This is **not** a plugin / backend. It's the host doing one of its core
//! jobs: mediating every plugin invocation. `plugin_host` already owns
//! concurrency caps and (in the design) `signed_fetch` credential injection;
//! pacing fits the same role. The host wraps every registered plugin in this
//! middleware before handing the resulting `Arc<dyn PluginContract>` to
//! callers, so backends opt out by configuration, not by code change.
//!
//! What it does:
//!
//! 1. **Paces** outbound calls with a token bucket (configurable per
//!    operation: puts, gets, peeks, deletes, plus a max-concurrency cap).
//! 2. **Respects backend signals** — when the inner plugin returns
//!    `PluginError::RateLimited { retry_after, .. }`, the middleware sleeps
//!    for `retry_after` (plus jitter) and retries. By default there is *no*
//!    upper bound on retries: a 1 GiB upload through a 1-req/sec backend
//!    just takes a long time, it does not fail.
//! 3. **Exponentially backs off** other transient errors
//!    (`Unavailable`, network glitches) up to `max_transient_attempts`.
//! 4. **Fails fast** on hard 4xx / `AuthFailure` / `NotSupported` —
//!    retrying those is pointless.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::Range;

use crate::contract::{
    DeleteResult, HealthReport, PeekResult, PluginContract, PutResult,
};
use crate::{PluginError, RateLimitScope, Result as PluginResult};

/// One token bucket's worth of rate state: steady-state rate + burst.
#[derive(Debug, Clone, Copy)]
pub struct RateBucket {
    pub per_sec: f64,
    pub burst: u32,
}

impl RateBucket {
    pub const fn new(per_sec: f64, burst: u32) -> Self {
        Self { per_sec, burst }
    }
    /// "No cap" for backends that don't rate-limit (local fs, in-memory).
    pub const fn unbounded() -> Self {
        Self {
            per_sec: 10_000.0,
            burst: 1024,
        }
    }
}

/// **The plugin's self-description.** Returned from
/// `PluginContract::rate_limit_profile`. Bundles every piece of rate-limit
/// knowledge the plugin author has about their backend so the host can wire
/// pacing, fall-back routing, and quota reporting from a single declaration
/// instead of separate configuration in `main.rs`.
#[derive(Clone)]
pub struct RateLimitProfile {
    pub label: String,
    pub puts: RateBucket,
    pub gets: RateBucket,
    pub peeks: RateBucket,
    pub deletes: RateBucket,
    /// Max outstanding inflight calls (any op).
    pub max_concurrent: u32,
    /// Per-object byte ceiling enforced by the backend (Telegram=50 MiB,
    /// Discord=25 MiB, etc.). The engine surfaces this so callers can
    /// chunk accordingly. `None` = no known cap.
    pub max_object_bytes: Option<u64>,
    /// Total account quota if the plugin author has a known number.
    /// The capacity planner uses this; reported via `os providers ls`.
    pub total_quota_bytes: Option<u64>,
    /// How to recognize a rate-limit signal on this backend's HTTP wire.
    /// Plugins use the same `Arc` in their internal `HttpClient`; the host
    /// keeps it on the profile so operators can audit per-plugin
    /// recognition rules and so non-HTTP plugins (LocalDirPlugin) can
    /// still register a no-op detector by accepting the default.
    pub detector: Arc<dyn crate::http::ratelimit::RateLimitDetector>,
}

impl std::fmt::Debug for RateLimitProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitProfile")
            .field("label", &self.label)
            .field("puts", &self.puts)
            .field("gets", &self.gets)
            .field("peeks", &self.peeks)
            .field("deletes", &self.deletes)
            .field("max_concurrent", &self.max_concurrent)
            .field("max_object_bytes", &self.max_object_bytes)
            .field("total_quota_bytes", &self.total_quota_bytes)
            .field("detector", &"<dyn RateLimitDetector>")
            .finish()
    }
}

impl RateLimitProfile {
    /// "I don't know my limits" — used by local-only / test plugins.
    pub fn unbounded() -> Self {
        Self {
            label: "unbounded".into(),
            puts: RateBucket::unbounded(),
            gets: RateBucket::unbounded(),
            peeks: RateBucket::unbounded(),
            deletes: RateBucket::unbounded(),
            max_concurrent: 64,
            max_object_bytes: None,
            total_quota_bytes: None,
            detector: Arc::new(crate::http::ratelimit::DefaultDetector),
        }
    }

    /// Conservative free-tier default for unknown HTTP backends:
    /// 1 op/sec, default Retry-After-aware detector.
    pub fn conservative(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            puts: RateBucket::new(1.0, 2),
            gets: RateBucket::new(2.0, 4),
            peeks: RateBucket::new(4.0, 8),
            deletes: RateBucket::new(1.0, 2),
            max_concurrent: 4,
            max_object_bytes: None,
            total_quota_bytes: None,
            detector: Arc::new(crate::http::ratelimit::DefaultDetector),
        }
    }
}

/// **Host-level retry / backoff policy.** Independent of any one plugin —
/// it applies the same way to all of them. This is the engine's behavior,
/// not the backend's characteristics.
#[derive(Debug, Clone)]
pub struct MiddlewarePolicy {
    /// How many transient retries we'll attempt for backends that don't
    /// emit `Retry-After`.
    pub max_transient_attempts: u32,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// `None` means "wait as long as the backend asks". Setting this gives
    /// callers a liveness ceiling.
    pub max_rate_limit_wait: Option<Duration>,
    pub jitter: Duration,
}

impl Default for MiddlewarePolicy {
    fn default() -> Self {
        Self {
            max_transient_attempts: 5,
            min_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
            max_rate_limit_wait: None,
            jitter: Duration::from_millis(50),
        }
    }
}

/// Internal config the middleware actually consumes. Constructed by joining
/// a `RateLimitProfile` (plugin-declared) with a `MiddlewarePolicy`
/// (host-declared). Existing call sites keep working.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub puts_burst: u32,
    pub puts_per_sec: f64,
    pub gets_burst: u32,
    pub gets_per_sec: f64,
    pub peeks_burst: u32,
    pub peeks_per_sec: f64,
    pub deletes_burst: u32,
    pub deletes_per_sec: f64,
    pub max_concurrent: u32,
    pub max_transient_attempts: u32,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub max_rate_limit_wait: Option<Duration>,
    pub jitter: Duration,
}

impl RateLimitConfig {
    /// Build a middleware config from the plugin's profile + the host's policy.
    pub fn from_profile(p: &RateLimitProfile, policy: &MiddlewarePolicy) -> Self {
        Self {
            puts_burst: p.puts.burst,
            puts_per_sec: p.puts.per_sec,
            gets_burst: p.gets.burst,
            gets_per_sec: p.gets.per_sec,
            peeks_burst: p.peeks.burst,
            peeks_per_sec: p.peeks.per_sec,
            deletes_burst: p.deletes.burst,
            deletes_per_sec: p.deletes.per_sec,
            max_concurrent: p.max_concurrent,
            max_transient_attempts: policy.max_transient_attempts,
            min_backoff: policy.min_backoff,
            max_backoff: policy.max_backoff,
            max_rate_limit_wait: policy.max_rate_limit_wait,
            jitter: policy.jitter,
        }
    }

    /// Equivalent to `from_profile(&unbounded(), &default_policy())`.
    pub fn unbounded() -> Self {
        Self::from_profile(&RateLimitProfile::unbounded(), &MiddlewarePolicy::default())
    }

    /// Convenience for tests / fixtures.
    pub fn conservative() -> Self {
        Self::from_profile(
            &RateLimitProfile::conservative("test"),
            &MiddlewarePolicy::default(),
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitStats {
    pub waited_for_token_total_ms: u64,
    pub waited_for_rate_limit_total_ms: u64,
    pub rate_limit_hits: u64,
    pub transient_retries: u64,
    pub successful_calls: u64,
    pub gave_up: u64,
}

pub struct RateLimitMiddleware {
    inner: Arc<dyn PluginContract>,
    cfg: RateLimitConfig,
    stats: tokio::sync::Mutex<RateLimitStats>,
    sem: tokio::sync::Semaphore,
    bucket_put: tokio::sync::Mutex<TokenBucket>,
    bucket_get: tokio::sync::Mutex<TokenBucket>,
    bucket_peek: tokio::sync::Mutex<TokenBucket>,
    bucket_delete: tokio::sync::Mutex<TokenBucket>,
    /// Set when the inner plugin returned RateLimited; lets the dispatcher
    /// route around this provider until the cooldown elapses without paying
    /// the cost of locking the bucket.
    cooldown_until: tokio::sync::Mutex<Option<Instant>>,
    label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Put,
    Get,
    Peek,
    Delete,
}

/// What a single middleware looks like to a dispatcher *right now*.
#[derive(Debug, Clone, Copy)]
pub struct CapacitySnapshot {
    /// Tokens currently in the bucket for `op` (post-refill).
    pub tokens_available: f64,
    /// How long until at least one token is available. `Duration::ZERO` if
    /// `tokens_available >= 1.0` and no cooldown is active.
    pub estimated_wait: Duration,
    /// Set if the backend most recently asked us to back off until this
    /// instant. Dispatcher uses this to skip the provider until it elapses.
    pub cooldown_remaining: Duration,
    /// Number of inflight operations through this middleware (rough; bounded
    /// by `max_concurrent`).
    pub inflight: u32,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    burst: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: u32, per_sec: f64) -> Self {
        Self {
            tokens: burst as f64,
            burst: burst as f64,
            refill_per_sec: per_sec,
            last_refill: Instant::now(),
        }
    }
    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.burst);
        self.last_refill = now;
    }
    /// Returns the duration to wait before a token would be available, then
    /// (when called again) deducts the token. Cooperative, so caller must
    /// loop on this if multiple awaiters race.
    fn try_acquire(&mut self) -> Result<(), Duration> {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_per_sec;
            Err(Duration::from_secs_f64(secs.max(0.001)))
        }
    }
}

impl RateLimitMiddleware {
    pub fn new(inner: Arc<dyn PluginContract>, cfg: RateLimitConfig) -> Self {
        let max_concurrent = cfg.max_concurrent.max(1) as usize;
        Self {
            sem: tokio::sync::Semaphore::new(max_concurrent),
            bucket_put: tokio::sync::Mutex::new(TokenBucket::new(cfg.puts_burst, cfg.puts_per_sec)),
            bucket_get: tokio::sync::Mutex::new(TokenBucket::new(cfg.gets_burst, cfg.gets_per_sec)),
            bucket_peek: tokio::sync::Mutex::new(TokenBucket::new(cfg.peeks_burst, cfg.peeks_per_sec)),
            bucket_delete: tokio::sync::Mutex::new(TokenBucket::new(cfg.deletes_burst, cfg.deletes_per_sec)),
            stats: tokio::sync::Mutex::new(RateLimitStats::default()),
            cooldown_until: tokio::sync::Mutex::new(None),
            cfg,
            inner,
            label: "rate-limit".into(),
        }
    }

    pub fn with_label(mut self, l: impl Into<String>) -> Self {
        self.label = l.into();
        self
    }

    /// Non-blocking peek at how ready the middleware is for `op`. The
    /// dispatcher uses this to pick the highest-capacity candidate.
    pub async fn capacity_snapshot(&self, op: Op) -> CapacitySnapshot {
        let bucket = match op {
            Op::Put => &self.bucket_put,
            Op::Get => &self.bucket_get,
            Op::Peek => &self.bucket_peek,
            Op::Delete => &self.bucket_delete,
        };
        let cooldown_remaining = {
            let g = self.cooldown_until.lock().await;
            match *g {
                Some(t) => t.checked_duration_since(Instant::now()).unwrap_or_default(),
                None => Duration::ZERO,
            }
        };
        let (tokens_available, est) = {
            let mut b = bucket.lock().await;
            b.refill();
            let est = if b.tokens >= 1.0 {
                Duration::ZERO
            } else {
                let needed = 1.0 - b.tokens;
                Duration::from_secs_f64((needed / b.refill_per_sec).max(0.001))
            };
            (b.tokens, est)
        };
        let inflight = self
            .cfg
            .max_concurrent
            .saturating_sub(self.sem.available_permits() as u32);
        CapacitySnapshot {
            tokens_available,
            estimated_wait: est.max(cooldown_remaining),
            cooldown_remaining,
            inflight,
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.cfg
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub async fn snapshot_stats(&self) -> RateLimitStats {
        *self.stats.lock().await
    }

    async fn wait_for_token(&self, op: Op) {
        let bucket = match op {
            Op::Put => &self.bucket_put,
            Op::Get => &self.bucket_get,
            Op::Peek => &self.bucket_peek,
            Op::Delete => &self.bucket_delete,
        };
        let started = Instant::now();
        loop {
            let wait = {
                let mut b = bucket.lock().await;
                match b.try_acquire() {
                    Ok(()) => break,
                    Err(d) => d,
                }
            };
            tokio::time::sleep(wait + jitter(self.cfg.jitter)).await;
        }
        let waited = started.elapsed().as_millis() as u64;
        if waited > 0 {
            self.stats.lock().await.waited_for_token_total_ms += waited;
        }
    }

    /// The retry loop shared by every op. Calls `f`, handles `RateLimited`
    /// (sleep + retry forever subject to `max_rate_limit_wait`), handles
    /// generic transient failures with exponential backoff up to
    /// `max_transient_attempts`, fails fast on hard errors.
    async fn run<T, F, Fut>(&self, op: Op, mut f: F) -> PluginResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = PluginResult<T>>,
    {
        let _permit = match self.sem.acquire().await {
            Ok(p) => p,
            Err(_) => return Err(PluginError::Unavailable("semaphore closed".into())),
        };
        self.wait_for_token(op).await;

        let started = Instant::now();
        let mut transient_attempts = 0u32;
        let mut backoff = self.cfg.min_backoff;
        let mut total_rl_wait = Duration::ZERO;

        loop {
            match f().await {
                Ok(v) => {
                    self.stats.lock().await.successful_calls += 1;
                    return Ok(v);
                }
                Err(PluginError::RateLimited { retry_after, scope }) => {
                    let sleep_for = retry_after + jitter(self.cfg.jitter);
                    if let Some(cap) = self.cfg.max_rate_limit_wait {
                        if total_rl_wait + sleep_for > cap {
                            self.stats.lock().await.gave_up += 1;
                            return Err(PluginError::RateLimited { retry_after, scope });
                        }
                    }
                    {
                        let mut s = self.stats.lock().await;
                        s.rate_limit_hits += 1;
                        s.waited_for_rate_limit_total_ms += sleep_for.as_millis() as u64;
                    }
                    // Tell the dispatcher to skip this provider until the
                    // backend's wait expires. Subsequent operations from
                    // *other callers* see this via capacity_snapshot.
                    {
                        let mut g = self.cooldown_until.lock().await;
                        *g = Some(Instant::now() + sleep_for);
                    }
                    tracing::warn!(
                        plugin = %self.label,
                        op = ?op,
                        retry_after_ms = sleep_for.as_millis(),
                        scope = %scope,
                        elapsed_total_ms = started.elapsed().as_millis(),
                        "rate-limited; sleeping then retrying"
                    );
                    tokio::time::sleep(sleep_for).await;
                    total_rl_wait += sleep_for;
                    // Don't count rate-limit retries against the transient cap.
                    continue;
                }
                Err(PluginError::Unavailable(msg)) | Err(PluginError::Io(msg)) => {
                    transient_attempts += 1;
                    if transient_attempts > self.cfg.max_transient_attempts {
                        self.stats.lock().await.gave_up += 1;
                        return Err(PluginError::Unavailable(msg));
                    }
                    self.stats.lock().await.transient_retries += 1;
                    let sleep_for = backoff + jitter(self.cfg.jitter);
                    tracing::warn!(
                        plugin = %self.label,
                        op = ?op,
                        attempt = transient_attempts,
                        backoff_ms = sleep_for.as_millis(),
                        cause = %msg,
                        "transient failure; retrying with backoff"
                    );
                    tokio::time::sleep(sleep_for).await;
                    backoff = (backoff * 2).min(self.cfg.max_backoff);
                    continue;
                }
                Err(other) => {
                    // Hard 4xx, AuthFailure, NotFound, NotSupported,
                    // IdempotencyViolation: not retryable.
                    return Err(other);
                }
            }
        }
    }
}

fn jitter(max: Duration) -> Duration {
    use rand::Rng;
    let micros = rand::thread_rng().gen_range(0..=max.as_micros() as u64);
    Duration::from_micros(micros)
}

#[async_trait]
impl PluginContract for RateLimitMiddleware {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> PluginResult<PutResult> {
        let payload_owned = payload.to_vec();
        let hint_owned = hint.clone();
        self.run(Op::Put, move || {
            let inner = self.inner.clone();
            let p = payload_owned.clone();
            let h = hint_owned.clone();
            async move { inner.put(&p, &h).await }
        })
        .await
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        let h = handle.clone();
        let r = range;
        self.run(Op::Get, move || {
            let inner = self.inner.clone();
            let hh = h.clone();
            async move { inner.get(&hh, r).await }
        })
        .await
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        let h = handle.clone();
        self.run(Op::Peek, move || {
            let inner = self.inner.clone();
            let hh = h.clone();
            async move { inner.peek(&hh).await }
        })
        .await
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        let h = handle.clone();
        self.run(Op::Delete, move || {
            let inner = self.inner.clone();
            let hh = h.clone();
            async move { inner.delete(&hh).await }
        })
        .await
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        // Health checks bypass the bucket — they're cheap and we want them
        // to be honest about backend status.
        self.inner.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Inner plugin that returns RateLimited for the first N calls then
    /// succeeds, to verify the wrapper waits and retries.
    struct FlakyPlugin {
        fail_first: u32,
        seen: AtomicU32,
    }

    #[async_trait]
    impl PluginContract for FlakyPlugin {
        async fn put(
            &self,
            _payload: &[u8],
            _hint: &PutHint,
        ) -> PluginResult<PutResult> {
            let n = self.seen.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                return Err(PluginError::RateLimited {
                    retry_after: Duration::from_millis(50),
                    scope: RateLimitScope::Global,
                });
            }
            Ok(PutResult {
                handle: NativeHandle(format!("h-{n}").into_bytes()),
                handle_changed: true,
                prior_handle_state: None,
                stored_at: os_types::Timestamp::from_string("test"),
                quota_reclaimed: os_types::QuotaReclaimed::Unknown,
                tombstone_clears_at: None,
            })
        }
        async fn get(
            &self,
            _handle: &NativeHandle,
            _range: Option<Range>,
        ) -> PluginResult<Vec<u8>> {
            Ok(b"ok".to_vec())
        }
        async fn peek(&self, _handle: &NativeHandle) -> PluginResult<PeekResult> {
            unimplemented!()
        }
        async fn delete(&self, _handle: &NativeHandle) -> PluginResult<DeleteResult> {
            unimplemented!()
        }
        async fn health(&self) -> PluginResult<HealthReport> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn rate_limited_calls_eventually_succeed() {
        let inner = Arc::new(FlakyPlugin {
            fail_first: 5,
            seen: AtomicU32::new(0),
        });
        let mut cfg = RateLimitConfig::unbounded();
        cfg.jitter = Duration::from_millis(0);
        let wrap = RateLimitMiddleware::new(inner.clone(), cfg);
        let started = Instant::now();
        let r = wrap.put(b"x", &PutHint::default()).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(r.handle.0, b"h-5".to_vec());
        // We sleep 50ms × 5 retries = 250ms minimum (plus token-bucket overhead).
        assert!(elapsed >= Duration::from_millis(240), "elapsed={elapsed:?}");
        let stats = wrap.snapshot_stats().await;
        assert_eq!(stats.successful_calls, 1);
        assert_eq!(stats.rate_limit_hits, 5);
        assert!(stats.waited_for_rate_limit_total_ms >= 240);
    }

    /// 200 calls through a 1/sec bucket — no errors at all, just paced.
    /// We use 50/sec to keep the test fast (~4 sec).
    #[tokio::test]
    async fn token_bucket_paces_calls() {
        let inner = Arc::new(FlakyPlugin {
            fail_first: 0,
            seen: AtomicU32::new(0),
        });
        let mut cfg = RateLimitConfig::unbounded();
        cfg.puts_burst = 5;
        cfg.puts_per_sec = 50.0;
        cfg.jitter = Duration::from_millis(0);
        let wrap = RateLimitMiddleware::new(inner, cfg);
        let started = Instant::now();
        for _ in 0..200 {
            wrap.put(b"x", &PutHint::default()).await.unwrap();
        }
        let elapsed = started.elapsed();
        // 200 calls, 5 burst, 50/sec ⇒ (200-5)/50 = 3.9 sec minimum.
        assert!(
            elapsed >= Duration::from_millis(3500),
            "expected paced, got {elapsed:?}"
        );
    }
}
