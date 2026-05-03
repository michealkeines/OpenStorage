//! Per-provider observed idempotency-window tracking.
//!
//! ROUTING.md §6.5. Plugins may declare an idempotency window
//! (`IdempotentPut` flag + `idempotency_window_seconds` scalar) so the
//! retry path can dedupe safely. Reality drifts:
//!
//! - Catbox / uguu / x0 declare nothing — every retry produces a new
//!   handle.
//! - Telegraph claims persistent pages but creates a new URL on
//!   retry.
//! - Some commercial backends advertise 1 h dedup but degrade to
//!   ≤ 60 s under load.
//!
//! The tracker counts observed violations — a retry within the
//! declared window that produced a *different* handle than the
//! original. Past a threshold, the effective window is derated to a
//! safe "no idempotency" position; subsequent retry-after-RateLimited
//! flows skip the dedup assumption and accept that each retry is a
//! fresh allocation (handled by the shadow registry).
//!
//! Today the tracker exposes the API and the data structure; deeper
//! integration with the retry path lives in a follow-up step.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use os_types::ProviderId;

#[derive(Debug, Clone, Copy)]
pub struct IdempotencyTrackerConfig {
    /// Violations threshold before the engine derates the declared
    /// window to "no idempotency."
    pub violations_to_derate: u32,
    /// Window for the violation count.
    pub observation_window: Duration,
}

impl Default for IdempotencyTrackerConfig {
    fn default() -> Self {
        Self {
            violations_to_derate: 3,
            observation_window: Duration::from_secs(60 * 60),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ProviderIdempotency {
    /// Wall-clock instants of observed violations within the
    /// observation window.
    violations: Vec<Instant>,
}

pub struct IdempotencyTracker {
    inner: RwLock<HashMap<ProviderId, ProviderIdempotency>>,
    cfg: IdempotencyTrackerConfig,
}

impl Default for IdempotencyTracker {
    fn default() -> Self {
        Self::with_config(IdempotencyTrackerConfig::default())
    }
}

impl IdempotencyTracker {
    pub fn with_config(cfg: IdempotencyTrackerConfig) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            cfg,
        }
    }

    /// Caller observed a retry-within-window that produced a
    /// different handle than the original. Bumps the count.
    pub fn record_violation(&self, provider: ProviderId) {
        let now = Instant::now();
        let mut g = self.inner.write().expect("idempotency map");
        let entry = g.entry(provider).or_default();
        entry.violations.push(now);
        prune(&mut entry.violations, now, self.cfg.observation_window);
    }

    /// True iff this provider has observed enough violations to be
    /// considered effectively non-idempotent. Callers SHOULD avoid
    /// the dedup-on-retry assumption for this provider's writes.
    pub fn is_unreliable(&self, provider: ProviderId) -> bool {
        let now = Instant::now();
        let g = self.inner.read().expect("idempotency map");
        match g.get(&provider) {
            Some(e) => {
                let recent = e
                    .violations
                    .iter()
                    .filter(|t| now.duration_since(**t) <= self.cfg.observation_window)
                    .count() as u32;
                recent >= self.cfg.violations_to_derate
            }
            None => false,
        }
    }

    /// Recent violation count within the observation window. Used by
    /// metrics / `os providers ls`.
    pub fn violation_count(&self, provider: ProviderId) -> u32 {
        let now = Instant::now();
        let g = self.inner.read().expect("idempotency map");
        g.get(&provider)
            .map(|e| {
                e.violations
                    .iter()
                    .filter(|t| now.duration_since(**t) <= self.cfg.observation_window)
                    .count() as u32
            })
            .unwrap_or(0)
    }
}

fn prune(v: &mut Vec<Instant>, now: Instant, window: Duration) {
    v.retain(|t| now.duration_since(*t) <= window);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> ProviderId {
        ProviderId::new_v7()
    }

    #[test]
    fn unknown_provider_is_reliable() {
        let t = IdempotencyTracker::default();
        assert!(!t.is_unreliable(pid()));
    }

    #[test]
    fn flips_unreliable_after_threshold() {
        let t = IdempotencyTracker::default(); // threshold=3
        let p = pid();
        t.record_violation(p);
        t.record_violation(p);
        assert!(!t.is_unreliable(p));
        t.record_violation(p);
        assert!(t.is_unreliable(p));
        assert_eq!(t.violation_count(p), 3);
    }

    #[test]
    fn rolling_window_prunes_stale() {
        let t = IdempotencyTracker::with_config(IdempotencyTrackerConfig {
            violations_to_derate: 2,
            observation_window: Duration::from_millis(50),
        });
        let p = pid();
        t.record_violation(p);
        t.record_violation(p);
        assert!(t.is_unreliable(p));
        std::thread::sleep(Duration::from_millis(80));
        // Stale entries pruned on next record.
        t.record_violation(p);
        assert_eq!(t.violation_count(p), 1);
        assert!(!t.is_unreliable(p));
    }
}
