//! Multi-backend dispatcher.
//!
//! Given a *list of candidates*, the dispatcher:
//!
//! 1. asks each candidate's middleware for a `CapacitySnapshot`,
//! 2. sorts by `estimated_wait` ascending (most-ready first), break ties
//!    by `tokens_available` descending,
//! 3. tries the head, on `RateLimited` advances to the next, etc.
//! 4. exhausting the list returns the last error.
//!
//! Why this exists: with many small-capacity backends (think 50 free-tier
//! accounts at 1 req/sec each), the dispatcher distributes load so that
//! aggregate throughput is the *sum* of the per-provider rates, not the
//! min.
//!
//! Where this fits relative to placement:
//!
//! - `placement` decides the **canonical** primary for each shard (content
//!   hash → provider, with the trust-group diversity rule).
//! - `PoolDispatcher` decides which provider **actually** receives the
//!   bytes when the canonical primary is busy. Caller hands it a list of
//!   candidates that already satisfy the diversity rule (typically the
//!   primary plus other providers in the same trust group).
//!
//! For reads, the candidate set is `(provider_id, native_handle)` pairs —
//! valid only when the same content is replicated across multiple shards.
//! With EC `(k=1, n=1)` the candidate set has one element and the
//! dispatcher degenerates gracefully.

use std::sync::Arc;
use std::time::Duration;

use os_entities::{NativeHandle, PutHint};
use os_types::{ProviderId, Range};

use crate::contract::{PluginContract, PutResult};
use crate::host::Host;
use crate::rate_limit::{CapacitySnapshot, Op};
use crate::{PluginError, Result as PluginResult};

#[derive(Debug, Clone, Copy)]
pub struct DispatcherConfig {
    /// Hard ceiling on how many candidates a single op walks through before
    /// giving up. The default is "all of them" — set to a smaller number
    /// when liveness matters more than the chance of finding a willing
    /// backend.
    pub max_candidates: Option<u32>,
    /// If a candidate's `cooldown_remaining` is longer than this, skip it
    /// without even attempting (it will hit the rate limit again
    /// immediately). `None` means always try.
    pub skip_if_cooldown_exceeds: Option<Duration>,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            max_candidates: None,
            skip_if_cooldown_exceeds: Some(Duration::from_secs(30)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PutDispatched {
    pub handle: NativeHandle,
    pub provider_id: ProviderId,
    pub attempts: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone)]
pub struct GetDispatched {
    pub bytes: Vec<u8>,
    pub provider_id: ProviderId,
    pub attempts: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone)]
pub struct RankedCandidate {
    pub provider_id: ProviderId,
    pub snapshot: CapacitySnapshot,
}

pub struct PoolDispatcher;

impl PoolDispatcher {
    /// Walk a candidate list ordered by current capacity. The first one to
    /// accept the put wins.
    pub async fn put_with_fallback(
        host: &Host,
        candidates: &[ProviderId],
        payload: &[u8],
        hint: &PutHint,
        cfg: DispatcherConfig,
    ) -> PluginResult<PutDispatched> {
        if candidates.is_empty() {
            return Err(PluginError::Plugin("no candidates".into()));
        }
        let ranked = Self::rank(host, Op::Put, candidates).await;
        let breaker = host.circuit_breaker();
        let mut attempts = 0u32;
        let mut skipped = 0u32;
        let mut last_err: Option<PluginError> = None;
        let limit = cfg.max_candidates.map(|n| n as usize).unwrap_or(usize::MAX);
        for rc in ranked.iter().take(limit) {
            if let Some(cap) = cfg.skip_if_cooldown_exceeds {
                if rc.snapshot.cooldown_remaining > cap {
                    skipped += 1;
                    continue;
                }
            }
            // ROUTING.md §6.2 — skip candidates whose Put circuit is
            // currently Open. HalfOpen passes through (the call itself
            // is the probe).
            if !breaker.permits(rc.provider_id, Op::Put).permits_now() {
                skipped += 1;
                continue;
            }
            let plugin = match host.get_chunk(rc.provider_id) {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            attempts += 1;
            match plugin.put(payload, hint).await {
                Ok(r) => {
                    return Ok(PutDispatched {
                        handle: r.handle,
                        provider_id: rc.provider_id,
                        attempts,
                        skipped,
                    });
                }
                Err(PluginError::RateLimited { .. }) | Err(PluginError::Unavailable(_)) => {
                    last_err = Some(PluginError::Unavailable(format!(
                        "candidate {} unavailable",
                        rc.provider_id
                    )));
                    continue;
                }
                Err(other) => {
                    // Hard error on this candidate (auth, not-supported,
                    // 4xx) — surface immediately.
                    return Err(other);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            PluginError::Plugin("all candidates exhausted".into())
        }))
    }

    /// Walk replica candidates for a read. Each entry is `(provider_id,
    /// native_handle)` because each provider has its own handle for the
    /// same chunk.
    pub async fn get_with_fallback(
        host: &Host,
        candidates: &[(ProviderId, NativeHandle)],
        range: Option<Range>,
        cfg: DispatcherConfig,
    ) -> PluginResult<GetDispatched> {
        if candidates.is_empty() {
            return Err(PluginError::Plugin("no candidates".into()));
        }
        let ids: Vec<ProviderId> = candidates.iter().map(|(p, _)| *p).collect();
        let ranked = Self::rank(host, Op::Get, &ids).await;
        let breaker = host.circuit_breaker();
        let mut attempts = 0u32;
        let mut skipped = 0u32;
        let mut last_err: Option<PluginError> = None;
        let limit = cfg.max_candidates.map(|n| n as usize).unwrap_or(usize::MAX);
        for rc in ranked.iter().take(limit) {
            if let Some(cap) = cfg.skip_if_cooldown_exceeds {
                if rc.snapshot.cooldown_remaining > cap {
                    skipped += 1;
                    continue;
                }
            }
            // ROUTING.md §6.2 — skip candidates whose Get circuit is Open.
            if !breaker.permits(rc.provider_id, Op::Get).permits_now() {
                skipped += 1;
                continue;
            }
            let handle = match candidates.iter().find(|(p, _)| *p == rc.provider_id) {
                Some((_, h)) => h.clone(),
                None => continue,
            };
            let plugin = match host.get_chunk(rc.provider_id) {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            attempts += 1;
            match plugin.get(&handle, range).await {
                Ok(b) => {
                    return Ok(GetDispatched {
                        bytes: b,
                        provider_id: rc.provider_id,
                        attempts,
                        skipped,
                    });
                }
                Err(PluginError::RateLimited { .. }) | Err(PluginError::Unavailable(_)) => {
                    last_err = Some(PluginError::Unavailable(format!(
                        "candidate {} unavailable",
                        rc.provider_id
                    )));
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            PluginError::Plugin("all candidates exhausted".into())
        }))
    }

    /// Rank candidates for `op` by readiness. Most-ready first.
    pub async fn rank(host: &Host, op: Op, candidates: &[ProviderId]) -> Vec<RankedCandidate> {
        let mut out = Vec::with_capacity(candidates.len());
        for id in candidates {
            let snapshot = match host.middleware_for(*id) {
                Some(mw) => mw.capacity_snapshot(op).await,
                None => CapacitySnapshot {
                    tokens_available: f64::INFINITY,
                    estimated_wait: Duration::ZERO,
                    cooldown_remaining: Duration::ZERO,
                    inflight: 0,
                },
            };
            out.push(RankedCandidate {
                provider_id: *id,
                snapshot,
            });
        }
        out.sort_by(|a, b| {
            a.snapshot
                .estimated_wait
                .cmp(&b.snapshot.estimated_wait)
                .then(
                    b.snapshot
                        .tokens_available
                        .partial_cmp(&a.snapshot.tokens_available)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.snapshot.inflight.cmp(&b.snapshot.inflight))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use crate::contract::{
        DeleteResult, HealthReport, PeekResult, PluginContract, PutResult,
    };
    use crate::rate_limit::RateLimitConfig;
    use crate::RateLimitScope;

    /// A toy plugin that succeeds N times per second. Tracks how many
    /// successful puts it served.
    struct Capped {
        rate_per_sec: u32,
        served: AtomicU32,
        last_window: std::sync::Mutex<Instant>,
        served_this_window: std::sync::Mutex<u32>,
        name: &'static str,
    }

    impl Capped {
        fn new(name: &'static str, rate_per_sec: u32) -> Arc<Self> {
            Arc::new(Self {
                rate_per_sec,
                served: AtomicU32::new(0),
                last_window: std::sync::Mutex::new(Instant::now()),
                served_this_window: std::sync::Mutex::new(0),
                name,
            })
        }
    }

    #[async_trait]
    impl PluginContract for Capped {
        async fn put(
            &self,
            _payload: &[u8],
            _hint: &PutHint,
        ) -> PluginResult<PutResult> {
            let mut last = self.last_window.lock().unwrap();
            let mut served = self.served_this_window.lock().unwrap();
            if last.elapsed() >= Duration::from_secs(1) {
                *last = Instant::now();
                *served = 0;
            }
            if *served >= self.rate_per_sec {
                return Err(PluginError::RateLimited {
                    retry_after: Duration::from_millis(50),
                    scope: RateLimitScope::Global,
                });
            }
            *served += 1;
            self.served.fetch_add(1, Ordering::SeqCst);
            Ok(PutResult {
                handle: NativeHandle(self.name.as_bytes().to_vec()),
                handle_changed: true,
                prior_handle_state: None,
                stored_at: os_types::Timestamp::from_string("test"),
                quota_reclaimed: os_types::QuotaReclaimed::Unknown,
                tombstone_clears_at: None,
            })
        }
        async fn get(
            &self,
            _h: &NativeHandle,
            _r: Option<Range>,
        ) -> PluginResult<Vec<u8>> {
            Ok(b"".into())
        }
        async fn peek(&self, _h: &NativeHandle) -> PluginResult<PeekResult> {
            unimplemented!()
        }
        async fn delete(&self, _h: &NativeHandle) -> PluginResult<DeleteResult> {
            unimplemented!()
        }
        async fn health(&self) -> PluginResult<HealthReport> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn three_backends_at_one_per_sec_serve_in_parallel() {
        let host = Host::new();
        let mut cfg = RateLimitConfig::unbounded();
        cfg.jitter = Duration::from_millis(0);

        let a = Capped::new("A", 1);
        let b = Capped::new("B", 1);
        let c = Capped::new("C", 1);

        let id_a = ProviderId::new_v7();
        let id_b = ProviderId::new_v7();
        let id_c = ProviderId::new_v7();

        host.register_chunk_with_config(id_a, a.clone(), cfg.clone());
        host.register_chunk_with_config(id_b, b.clone(), cfg.clone());
        host.register_chunk_with_config(id_c, c.clone(), cfg);

        let candidates = vec![id_a, id_b, id_c];
        let started = Instant::now();
        for _ in 0..6 {
            let r = PoolDispatcher::put_with_fallback(
                &host,
                &candidates,
                b"x",
                &PutHint::default(),
                DispatcherConfig::default(),
            )
            .await
            .unwrap();
            let _ = r;
        }
        let elapsed = started.elapsed();

        // Each backend serves at most 1/sec. With three of them and a
        // dispatcher that fans out, six puts should complete in roughly
        // ~2 seconds (3 succeed in window 1, 3 succeed in window 2),
        // not in 6 if all calls had gone to the first.
        assert!(
            elapsed < Duration::from_secs(4),
            "expected dispatcher to fan out; elapsed={elapsed:?}"
        );

        // Each backend should have served at least once.
        let total = a.served.load(Ordering::SeqCst)
            + b.served.load(Ordering::SeqCst)
            + c.served.load(Ordering::SeqCst);
        assert_eq!(total, 6, "served totals A={} B={} C={}",
            a.served.load(Ordering::SeqCst),
            b.served.load(Ordering::SeqCst),
            c.served.load(Ordering::SeqCst));
        // None of the three should have served zero — verifies fan-out.
        assert!(a.served.load(Ordering::SeqCst) >= 1);
        assert!(b.served.load(Ordering::SeqCst) >= 1);
        assert!(c.served.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn single_candidate_degenerates_to_direct_call() {
        let host = Host::new();
        let p = Capped::new("solo", 100);
        let id = ProviderId::new_v7();
        host.register_chunk_with_config(id, p, RateLimitConfig::unbounded());

        let r = PoolDispatcher::put_with_fallback(
            &host,
            &[id],
            b"x",
            &PutHint::default(),
            DispatcherConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(r.attempts, 1);
        assert_eq!(r.provider_id, id);
    }

    /// ROUTING.md §13 Step 9 — the dispatcher consults the circuit
    /// breaker per candidate and skips any provider whose Put circuit
    /// is currently Open. With the Open candidate first, the
    /// dispatcher must reroute to the second.
    #[tokio::test]
    async fn put_dispatcher_skips_open_candidates() {
        use crate::CircuitState;
        let host = Host::new();
        let breaker = host.circuit_breaker();
        let cfg = RateLimitConfig::unbounded();
        let primary = Capped::new("primary", 1000);
        let secondary = Capped::new("secondary", 1000);
        let id_primary = ProviderId::new_v7();
        let id_secondary = ProviderId::new_v7();
        host.register_chunk_with_config(id_primary, primary.clone(), cfg.clone());
        host.register_chunk_with_config(id_secondary, secondary.clone(), cfg);

        // Force primary's Put circuit Open by recording 5 failures (the
        // default failure_threshold).
        for _ in 0..5 {
            breaker.record_failure(id_primary, Op::Put);
        }
        match breaker.permits(id_primary, Op::Put) {
            CircuitState::Open { .. } => {}
            other => panic!("expected primary Open, got {other:?}"),
        }
        // Secondary is still Closed.
        assert_eq!(breaker.permits(id_secondary, Op::Put), CircuitState::Closed);

        // Dispatch with primary listed first; primary should be skipped.
        let r = PoolDispatcher::put_with_fallback(
            &host,
            &[id_primary, id_secondary],
            b"x",
            &PutHint::default(),
            DispatcherConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(r.provider_id, id_secondary, "should skip Open primary");
        assert!(
            r.skipped >= 1,
            "skip count should reflect Open primary; got {}",
            r.skipped
        );
        // Primary's plugin should not have been invoked.
        assert_eq!(primary.served.load(Ordering::SeqCst), 0);
        assert_eq!(secondary.served.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ranking_prefers_least_loaded() {
        let host = Host::new();
        // Tight bucket on busy: 1 burst, refill 0.5/sec.
        let busy_cfg = RateLimitConfig {
            puts_burst: 1,
            puts_per_sec: 0.5,
            jitter: Duration::from_millis(0),
            ..RateLimitConfig::unbounded()
        };
        let free_cfg = RateLimitConfig::unbounded();
        let busy = Capped::new("busy", 100);
        let free = Capped::new("free", 100);
        let id_busy = ProviderId::new_v7();
        let id_free = ProviderId::new_v7();
        host.register_chunk_with_config(id_busy, busy.clone(), busy_cfg);
        host.register_chunk_with_config(id_free, free.clone(), free_cfg);
        // Drain the busy one's only token.
        host.get_chunk(id_busy)
            .unwrap()
            .put(b"x", &PutHint::default())
            .await
            .unwrap();
        // Now ask the dispatcher; busy bucket is empty, free is full.
        let ranked = PoolDispatcher::rank(&host, Op::Put, &[id_busy, id_free]).await;
        assert_eq!(ranked[0].provider_id, id_free);
    }
}
