//! Per-provider self-throttling against operator ToS budgets.
//!
//! ROUTING.md §6.3. Where `CircuitBreaker` reacts to *failures*, the
//! `AbuseSensor` reacts to *successful but excessive* traffic that
//! will provoke a ToS-driven ban tomorrow if left unchecked. It's the
//! difference between "this provider just rate-limited me" (breaker)
//! and "I'm about to burn my Imgur Client-ID's daily quota" (sensor).
//!
//! Each provider declares `daily_op_budget` in its `RateLimitProfile`
//! (`None` = no declared cap). The sensor counts successful ops in a
//! rolling 24 h window and:
//!
//! - `usage / budget < warn_at`            → cost multiplier 1.0
//! - `warn_at  ≤ usage / budget < heavy_at` → cost multiplier 5.0
//! - `heavy_at ≤ usage / budget < 1.0`     → cost multiplier 50.0
//! - `usage ≥ budget`                       → `is_over_budget = true`
//!
//! `is_over_budget` is the only signal acted on today — providers in
//! that state are filtered out of `vault::current_pool`. The cost
//! multipliers are exposed for Stage 4's future weighted-cost ranking
//! (ROUTING.md §4.4) but not yet consumed.
//!
//! Concurrency: a single `RwLock<HashMap>`. Per-call cost is one
//! VecDeque push + amortized window prune; bounded by `budget` per
//! provider.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use os_types::ProviderId;

#[derive(Debug, Clone, Copy)]
pub struct AbuseSensorConfig {
    pub window: Duration,
    /// Fraction of `budget` at which we start applying a soft cost
    /// penalty (default 0.8 → multiplier 5.0).
    pub warn_at: f32,
    /// Fraction at which the penalty steepens (default 0.95 →
    /// multiplier 50.0).
    pub heavy_at: f32,
}

impl Default for AbuseSensorConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(24 * 60 * 60),
            warn_at: 0.8,
            heavy_at: 0.95,
        }
    }
}

#[derive(Debug, Clone)]
struct ProviderUsage {
    /// Plugin-declared cap. `None` = no declared cap; the sensor
    /// considers the provider always under-budget.
    daily_budget: Option<u32>,
    /// Wall-clock instants of successful ops in the last `window`.
    /// Pruned lazily on every record / query.
    timestamps: VecDeque<Instant>,
}

pub struct AbuseSensor {
    inner: RwLock<HashMap<ProviderId, ProviderUsage>>,
    cfg: AbuseSensorConfig,
}

impl Default for AbuseSensor {
    fn default() -> Self {
        Self::with_config(AbuseSensorConfig::default())
    }
}

impl AbuseSensor {
    pub fn with_config(cfg: AbuseSensorConfig) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            cfg,
        }
    }

    /// Set or update a provider's declared budget. Called once at
    /// `Host::register_chunk` time from the live plugin's
    /// `rate_limit_profile().daily_op_budget`. `None` clears the cap.
    pub fn set_budget(&self, provider: ProviderId, budget: Option<u32>) {
        let mut g = self.inner.write().expect("abuse sensor map");
        let entry = g.entry(provider).or_insert(ProviderUsage {
            daily_budget: None,
            timestamps: VecDeque::new(),
        });
        entry.daily_budget = budget;
    }

    /// Tally one successful op against `provider`. Pruning the window
    /// happens on every call so memory stays bounded by the budget.
    pub fn record_op(&self, provider: ProviderId) {
        let now = Instant::now();
        let mut g = self.inner.write().expect("abuse sensor map");
        let entry = g.entry(provider).or_insert(ProviderUsage {
            daily_budget: None,
            timestamps: VecDeque::new(),
        });
        entry.timestamps.push_back(now);
        prune(&mut entry.timestamps, now, self.cfg.window);
    }

    /// Number of successful ops in the current window.
    pub fn usage(&self, provider: ProviderId) -> u32 {
        let now = Instant::now();
        let g = self.inner.read().expect("abuse sensor map");
        match g.get(&provider) {
            Some(e) => e
                .timestamps
                .iter()
                .filter(|t| now.duration_since(**t) <= self.cfg.window)
                .count() as u32,
            None => 0,
        }
    }

    /// True iff this provider has hit (or exceeded) its declared cap
    /// for the current window. `None` budget always returns `false`.
    pub fn is_over_budget(&self, provider: ProviderId) -> bool {
        let g = self.inner.read().expect("abuse sensor map");
        let e = match g.get(&provider) {
            Some(e) => e,
            None => return false,
        };
        let budget = match e.daily_budget {
            Some(b) if b > 0 => b,
            Some(_) => 0, // explicitly zero budget means immediately over
            None => return false,
        };
        let now = Instant::now();
        let used = e
            .timestamps
            .iter()
            .filter(|t| now.duration_since(**t) <= self.cfg.window)
            .count() as u32;
        if e.daily_budget == Some(0) {
            return true;
        }
        used >= budget
    }

    /// Soft-penalty multiplier for Stage 4 cost ranking. Returns 1.0
    /// for under-budget providers, 5.0 once `warn_at` is crossed,
    /// 50.0 once `heavy_at` is crossed, and `f32::INFINITY` once the
    /// budget is met (the provider should already have been filtered;
    /// this is a backstop).
    pub fn cost_multiplier(&self, provider: ProviderId) -> f32 {
        let g = self.inner.read().expect("abuse sensor map");
        let e = match g.get(&provider) {
            Some(e) => e,
            None => return 1.0,
        };
        let budget = match e.daily_budget {
            Some(b) if b > 0 => b as f32,
            Some(_) => return f32::INFINITY,
            None => return 1.0,
        };
        let now = Instant::now();
        let used = e
            .timestamps
            .iter()
            .filter(|t| now.duration_since(**t) <= self.cfg.window)
            .count() as f32;
        let frac = used / budget;
        if frac >= 1.0 {
            f32::INFINITY
        } else if frac >= self.cfg.heavy_at {
            50.0
        } else if frac >= self.cfg.warn_at {
            5.0
        } else {
            1.0
        }
    }

    /// Snapshot for metrics / debugging.
    pub fn snapshot(&self) -> Vec<(ProviderId, u32, Option<u32>)> {
        let now = Instant::now();
        let g = self.inner.read().expect("abuse sensor map");
        g.iter()
            .map(|(pid, e)| {
                let used = e
                    .timestamps
                    .iter()
                    .filter(|t| now.duration_since(**t) <= self.cfg.window)
                    .count() as u32;
                (*pid, used, e.daily_budget)
            })
            .collect()
    }
}

fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = q.front() {
        if now.duration_since(*front) > window {
            q.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> ProviderId {
        ProviderId::new_v7()
    }

    #[test]
    fn unknown_provider_is_under_budget() {
        let s = AbuseSensor::default();
        assert!(!s.is_over_budget(pid()));
        assert_eq!(s.cost_multiplier(pid()), 1.0);
    }

    #[test]
    fn no_budget_means_never_over() {
        let s = AbuseSensor::default();
        let p = pid();
        s.set_budget(p, None);
        for _ in 0..100 {
            s.record_op(p);
        }
        assert!(!s.is_over_budget(p));
        assert_eq!(s.cost_multiplier(p), 1.0);
    }

    #[test]
    fn zero_budget_is_immediately_over() {
        let s = AbuseSensor::default();
        let p = pid();
        s.set_budget(p, Some(0));
        assert!(s.is_over_budget(p));
        assert_eq!(s.cost_multiplier(p), f32::INFINITY);
    }

    #[test]
    fn over_budget_at_threshold() {
        let s = AbuseSensor::default();
        let p = pid();
        s.set_budget(p, Some(10));
        for _ in 0..9 {
            s.record_op(p);
        }
        assert!(!s.is_over_budget(p));
        s.record_op(p);
        assert!(s.is_over_budget(p));
    }

    #[test]
    fn cost_multiplier_steps() {
        let s = AbuseSensor::default();
        let p = pid();
        s.set_budget(p, Some(100));
        // 0% usage → 1.0
        assert_eq!(s.cost_multiplier(p), 1.0);
        // 79% usage → 1.0 still
        for _ in 0..79 {
            s.record_op(p);
        }
        assert_eq!(s.cost_multiplier(p), 1.0);
        // 80% usage → 5.0
        s.record_op(p);
        assert_eq!(s.cost_multiplier(p), 5.0);
        // 95% usage → 50.0
        for _ in 0..15 {
            s.record_op(p);
        }
        assert_eq!(s.cost_multiplier(p), 50.0);
        // 100% usage → infinity
        for _ in 0..5 {
            s.record_op(p);
        }
        assert_eq!(s.cost_multiplier(p), f32::INFINITY);
    }

    #[test]
    fn rolling_window_prunes_stale_entries() {
        // Use a very short window for testability.
        let s = AbuseSensor::with_config(AbuseSensorConfig {
            window: Duration::from_millis(50),
            ..Default::default()
        });
        let p = pid();
        s.set_budget(p, Some(2));
        s.record_op(p);
        s.record_op(p);
        assert!(s.is_over_budget(p));
        std::thread::sleep(Duration::from_millis(80));
        // Stale entries pruned on next query — well, on next record.
        s.record_op(p); // forces prune in record path
        assert_eq!(s.usage(p), 1);
        assert!(!s.is_over_budget(p));
    }

    #[test]
    fn budget_change_takes_effect_immediately() {
        let s = AbuseSensor::default();
        let p = pid();
        s.set_budget(p, Some(10));
        for _ in 0..5 {
            s.record_op(p);
        }
        assert!(!s.is_over_budget(p));
        // Tighten cap retroactively.
        s.set_budget(p, Some(3));
        assert!(s.is_over_budget(p));
        // Loosen.
        s.set_budget(p, Some(100));
        assert!(!s.is_over_budget(p));
    }
}
