//! Per-(provider, op) circuit breaker.
//!
//! See ROUTING.md §6.2. Complements `HealthMonitor`:
//!
//! - `HealthMonitor` is *provider-level* and drives the
//!   `current_pool` filter (Active / Quarantined / Banned). It reacts
//!   to broad patterns (5 auth fails in 60 s, 5 corruption events
//!   ever, 10 network fails in 60 s) and decides whether the engine
//!   keeps the provider in placement at all.
//!
//! - `CircuitBreaker` is *per-(provider, op)* and drives the
//!   dispatcher's per-call routing. It reacts immediately to short
//!   bursts of failures on a single op and lets the dispatcher pick a
//!   different candidate. A provider may be `Closed` for `gets` while
//!   `Open` for `puts` (e.g., write quota exhausted but reads still
//!   work) — `HealthMonitor` wouldn't catch that asymmetry.
//!
//! State machine:
//!
//! ```text
//! Closed ── N consecutive failures ─────► Open { until: now + cooldown }
//!   ▲                                         │
//!   │                                         │ now ≥ until
//!   │ M consecutive successes                 ▼
//!   └─────────────── HalfOpen ◄────── (probes allowed)
//!                          │
//!                          │ failure
//!                          ▼
//!                       Open { until: now + cooldown × 2 }
//! ```
//!
//! Cooldown grows exponentially up to `max_cooldown`; resets on a
//! successful Closed transition.
//!
//! Concurrency: a single `RwLock<HashMap<…>>` keyed by
//! `(ProviderId, Op)`. Pool sizes × 4 ops = bounded; per-call lock
//! overhead is negligible against network latency.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use os_types::ProviderId;

use crate::rate_limit::Op;

/// Default thresholds — chosen for portfolio backends where short
/// 429-bursts are normal but sustained failure means rerouting.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    /// Closed → Open after this many consecutive failures.
    pub failure_threshold: u32,
    /// First Open period; doubles on each Open transition (capped at
    /// `max_cooldown`). Resets when the breaker closes.
    pub initial_cooldown: Duration,
    pub max_cooldown: Duration,
    /// HalfOpen → Closed after this many consecutive successes.
    pub success_threshold_to_close: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            initial_cooldown: Duration::from_secs(15),
            max_cooldown: Duration::from_secs(15 * 60),
            success_threshold_to_close: 2,
        }
    }
}

/// Public state. The dispatcher reads this via `permits` and either
/// proceeds (`Closed` / `HalfOpen`) or skips (`Open`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open { until: Instant },
    HalfOpen,
}

impl CircuitState {
    pub fn permits_now(self) -> bool {
        match self {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open { until } => Instant::now() >= until,
        }
    }
}

#[derive(Debug, Clone)]
struct BreakerEntry {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    current_cooldown: Duration,
}

impl BreakerEntry {
    fn new(initial_cooldown: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            current_cooldown: initial_cooldown,
        }
    }
}

pub struct CircuitBreaker {
    inner: RwLock<HashMap<(ProviderId, Op), BreakerEntry>>,
    cfg: CircuitBreakerConfig,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }
}

impl CircuitBreaker {
    pub fn with_config(cfg: CircuitBreakerConfig) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            cfg,
        }
    }

    /// Read the current state, advancing `Open → HalfOpen` if the
    /// cooldown has elapsed. Used by the dispatcher to decide whether
    /// to attempt a candidate.
    pub fn permits(&self, provider: ProviderId, op: Op) -> CircuitState {
        let now = Instant::now();
        // Fast read path: already Closed.
        {
            let g = self.inner.read().expect("breaker map");
            if let Some(e) = g.get(&(provider, op)) {
                match e.state {
                    CircuitState::Closed => return CircuitState::Closed,
                    CircuitState::Open { until } if now < until => {
                        return CircuitState::Open { until };
                    }
                    _ => {}
                }
            } else {
                return CircuitState::Closed;
            }
        }
        // Need to transition Open → HalfOpen on cooldown elapse.
        let mut g = self.inner.write().expect("breaker map");
        let e = g
            .entry((provider, op))
            .or_insert_with(|| BreakerEntry::new(self.cfg.initial_cooldown));
        if let CircuitState::Open { until } = e.state {
            if now >= until {
                e.state = CircuitState::HalfOpen;
                e.consecutive_successes = 0;
            }
        }
        e.state
    }

    /// Record a successful op outcome. May transition `HalfOpen →
    /// Closed` once `success_threshold_to_close` is reached.
    pub fn record_success(&self, provider: ProviderId, op: Op) {
        let mut g = self.inner.write().expect("breaker map");
        let e = g
            .entry((provider, op))
            .or_insert_with(|| BreakerEntry::new(self.cfg.initial_cooldown));
        e.consecutive_failures = 0;
        match e.state {
            CircuitState::Closed => {
                // Stay Closed; reset cooldown to initial in case it had
                // grown via prior cycles.
                e.current_cooldown = self.cfg.initial_cooldown;
            }
            CircuitState::HalfOpen => {
                e.consecutive_successes = e.consecutive_successes.saturating_add(1);
                if e.consecutive_successes >= self.cfg.success_threshold_to_close {
                    e.state = CircuitState::Closed;
                    e.current_cooldown = self.cfg.initial_cooldown;
                }
            }
            CircuitState::Open { .. } => {
                // Success despite Open is unusual (caller bypassed the
                // permits check). Treat as a probe; promote to HalfOpen
                // and credit the success.
                e.state = CircuitState::HalfOpen;
                e.consecutive_successes = 1;
            }
        }
    }

    /// Record a failed op outcome. May transition `Closed → Open` or
    /// `HalfOpen → Open`.
    pub fn record_failure(&self, provider: ProviderId, op: Op) {
        let mut g = self.inner.write().expect("breaker map");
        let e = g
            .entry((provider, op))
            .or_insert_with(|| BreakerEntry::new(self.cfg.initial_cooldown));
        e.consecutive_successes = 0;
        match e.state {
            CircuitState::Closed => {
                e.consecutive_failures = e.consecutive_failures.saturating_add(1);
                if e.consecutive_failures >= self.cfg.failure_threshold {
                    let until = Instant::now() + e.current_cooldown;
                    e.state = CircuitState::Open { until };
                }
            }
            CircuitState::HalfOpen => {
                // One failure in HalfOpen reverts to Open with a
                // bigger cooldown — the probe failed.
                e.current_cooldown = (e.current_cooldown * 2).min(self.cfg.max_cooldown);
                let until = Instant::now() + e.current_cooldown;
                e.state = CircuitState::Open { until };
            }
            CircuitState::Open { .. } => {
                // Already Open; no transition. Failure under Open
                // means the caller bypassed permits; we don't extend
                // the cooldown for a single such event.
            }
        }
    }

    /// Snapshot for metrics / debugging. Pure read.
    pub fn snapshot(&self) -> Vec<((ProviderId, Op), CircuitState)> {
        let g = self.inner.read().expect("breaker map");
        g.iter().map(|(k, v)| (*k, v.state)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> ProviderId {
        ProviderId::new_v7()
    }

    fn breaker_short() -> CircuitBreaker {
        CircuitBreaker::with_config(CircuitBreakerConfig {
            failure_threshold: 3,
            initial_cooldown: Duration::from_millis(50),
            max_cooldown: Duration::from_secs(1),
            success_threshold_to_close: 2,
        })
    }

    #[test]
    fn unknown_provider_op_pair_starts_closed() {
        let b = CircuitBreaker::default();
        assert_eq!(b.permits(pid(), Op::Put), CircuitState::Closed);
    }

    #[test]
    fn closed_to_open_after_threshold_failures() {
        let b = breaker_short();
        let p = pid();
        b.record_failure(p, Op::Put);
        b.record_failure(p, Op::Put);
        assert_eq!(b.permits(p, Op::Put), CircuitState::Closed);
        b.record_failure(p, Op::Put);
        match b.permits(p, Op::Put) {
            CircuitState::Open { .. } => {}
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn success_resets_failure_count() {
        let b = breaker_short();
        let p = pid();
        b.record_failure(p, Op::Put);
        b.record_failure(p, Op::Put);
        b.record_success(p, Op::Put);
        b.record_failure(p, Op::Put);
        b.record_failure(p, Op::Put);
        // Two failures since the success → not yet Open.
        assert_eq!(b.permits(p, Op::Put), CircuitState::Closed);
    }

    #[test]
    fn open_to_halfopen_after_cooldown_elapses() {
        let b = breaker_short();
        let p = pid();
        for _ in 0..3 {
            b.record_failure(p, Op::Put);
        }
        assert!(matches!(b.permits(p, Op::Put), CircuitState::Open { .. }));
        std::thread::sleep(Duration::from_millis(75));
        assert_eq!(b.permits(p, Op::Put), CircuitState::HalfOpen);
    }

    #[test]
    fn halfopen_to_closed_after_success_threshold() {
        let b = breaker_short();
        let p = pid();
        for _ in 0..3 {
            b.record_failure(p, Op::Put);
        }
        std::thread::sleep(Duration::from_millis(75));
        let _ = b.permits(p, Op::Put); // transitions to HalfOpen
        b.record_success(p, Op::Put);
        b.record_success(p, Op::Put);
        assert_eq!(b.permits(p, Op::Put), CircuitState::Closed);
    }

    #[test]
    fn halfopen_failure_returns_to_open_with_grown_cooldown() {
        let b = breaker_short();
        let p = pid();
        for _ in 0..3 {
            b.record_failure(p, Op::Put);
        }
        std::thread::sleep(Duration::from_millis(75));
        let _ = b.permits(p, Op::Put);
        b.record_failure(p, Op::Put);
        match b.permits(p, Op::Put) {
            CircuitState::Open { until } => {
                let remaining = until.saturating_duration_since(Instant::now());
                // Cooldown should now be ≥ initial × 2 (with some
                // slack for the sleep).
                assert!(
                    remaining >= Duration::from_millis(50),
                    "remaining={remaining:?}"
                );
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn per_op_state_is_independent() {
        let b = breaker_short();
        let p = pid();
        for _ in 0..3 {
            b.record_failure(p, Op::Put);
        }
        // Puts are Open.
        assert!(matches!(b.permits(p, Op::Put), CircuitState::Open { .. }));
        // Gets are still Closed for the same provider.
        assert_eq!(b.permits(p, Op::Get), CircuitState::Closed);
    }

    #[test]
    fn permits_now_helper() {
        assert!(CircuitState::Closed.permits_now());
        assert!(CircuitState::HalfOpen.permits_now());
        let past = Instant::now() - Duration::from_secs(1);
        assert!(CircuitState::Open { until: past }.permits_now());
        let future = Instant::now() + Duration::from_secs(60);
        assert!(!CircuitState::Open { until: future }.permits_now());
    }
}
