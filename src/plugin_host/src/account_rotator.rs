//! Multi-account rotator for `RequiresAccount` providers.
//!
//! ROUTING.md §6.6. Some providers gate per-account rate limits
//! (Imgur per Client-ID, Telegram per bot token, Mastodon per OAuth
//! token, GitHub per PAT). Holding *N* such tokens behind one
//! `provider_id` and dispatching round-robin across them turns a
//! single-account `puts_per_sec=1` provider into an aggregate
//! `N × 1` puts/sec without changing placement, diversity, or any
//! caller's view of the engine.
//!
//! Wire shape: each inner account is a fully-formed `dyn
//! PluginContract` (typically already wrapped in
//! `RateLimitMiddleware` so per-account rate limits are honored
//! independently). The rotator itself is registered with `Host`
//! through `register_chunk_unpaced` since the inner accounts already
//! pace themselves.
//!
//! Per-op semantics:
//! - `put` / `update` rotate per call, retrying on `RateLimited` /
//!   `Unavailable` until either some account succeeds or all are
//!   exhausted.
//! - `get` / `peek` / `delete` fan out to every account in turn — for
//!   a handle issued by account *i*, only account *i* knows it, so we
//!   try them all and the first non-NotFound wins.
//! - `health` reports `Healthy` if any account is healthy.
//!
//! Strategies:
//! - `RoundRobin` (implemented today): atomic counter, modulo N.
//! - `LeastUsed` (implemented today): per-account success counter,
//!   pick the minimum.
//! - `JitWithCooldown` (placeholder): keep cool accounts cool, only
//!   rotate when current is rate-limited. Future step.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::{
    CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile, QuotaReclaimed, QuotaState,
    Range, RateLimitState, Timestamp,
};

use crate::contract::{
    DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
};
use crate::rate_limit::{RateBucket, RateLimitProfile};
use crate::{PluginError, Result};

/// How to pick the next account on each call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStrategy {
    /// Modulo-N counter; uniform distribution.
    RoundRobin,
    /// Pick the account with the lowest cumulative successful op
    /// count. Ties break to lower index.
    LeastUsed,
}

pub struct AccountRotator {
    accounts: Vec<Arc<dyn PluginContract>>,
    strategy: AccountStrategy,
    next: AtomicUsize,
    /// Per-account successful-op count. Read by `LeastUsed`; updated
    /// by every successful op regardless of strategy so a future
    /// runtime-strategy switch sees an honest count.
    usage: Mutex<Vec<u32>>,
}

impl AccountRotator {
    /// Construct with N accounts. Panics if `accounts` is empty —
    /// callers must hand at least one.
    pub fn new(accounts: Vec<Arc<dyn PluginContract>>, strategy: AccountStrategy) -> Self {
        assert!(!accounts.is_empty(), "AccountRotator: empty account pool");
        let n = accounts.len();
        Self {
            accounts,
            strategy,
            next: AtomicUsize::new(0),
            usage: Mutex::new(vec![0u32; n]),
        }
    }

    /// Number of accounts in the pool.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    fn pick(&self) -> usize {
        match self.strategy {
            AccountStrategy::RoundRobin => {
                self.next.fetch_add(1, Ordering::Relaxed) % self.accounts.len()
            }
            AccountStrategy::LeastUsed => {
                let g = self.usage.lock().expect("usage mutex");
                g.iter()
                    .enumerate()
                    .min_by_key(|(_, c)| **c)
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            }
        }
    }

    fn record_use(&self, idx: usize) {
        if let Ok(mut g) = self.usage.lock() {
            if let Some(slot) = g.get_mut(idx) {
                *slot = slot.saturating_add(1);
            }
        }
    }

    /// Snapshot of per-account usage counts. Used by tests and metrics.
    pub fn usage_snapshot(&self) -> Vec<u32> {
        self.usage
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl PluginContract for AccountRotator {
    fn rate_limit_profile(&self) -> RateLimitProfile {
        // Merge: smallest size cap (any account would refuse a too-big
        // payload), sum of rate budgets and daily caps (capacity adds
        // when the strategy distributes evenly), most-permissive
        // update_capability (any account that supports update suffices
        // for slot-pool eligibility).
        let mut iter = self.accounts.iter().map(|a| a.rate_limit_profile());
        let first = iter.next().expect("non-empty rotator");
        let mut merged = first;
        for p in iter {
            merged.max_object_bytes = match (merged.max_object_bytes, p.max_object_bytes) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (None, x) | (x, None) => x,
            };
            merged.puts = sum_bucket(merged.puts, p.puts);
            merged.gets = sum_bucket(merged.gets, p.gets);
            merged.peeks = sum_bucket(merged.peeks, p.peeks);
            merged.deletes = sum_bucket(merged.deletes, p.deletes);
            merged.max_concurrent = merged.max_concurrent.saturating_add(p.max_concurrent);
            merged.total_quota_bytes = match (merged.total_quota_bytes, p.total_quota_bytes) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                (None, _) | (_, None) => None,
            };
            merged.daily_op_budget = match (merged.daily_op_budget, p.daily_op_budget) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                (None, _) | (_, None) => None,
            };
            if matches!(
                p.update_capability,
                os_types::UpdateCapability::TrueUpdate
            ) || matches!(
                merged.update_capability,
                os_types::UpdateCapability::None
            ) {
                merged.update_capability = p.update_capability;
            }
        }
        merged.label = format!(
            "{}-rotator({})",
            merged.label,
            self.accounts.len()
        );
        merged
    }

    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult> {
        let n = self.accounts.len();
        let mut last_err: Option<PluginError> = None;
        for _ in 0..n {
            let idx = self.pick();
            match self.accounts[idx].put(payload, hint).await {
                Ok(r) => {
                    self.record_use(idx);
                    return Ok(r);
                }
                Err(PluginError::RateLimited { .. })
                | Err(PluginError::Unavailable(_)) => {
                    last_err = Some(PluginError::Unavailable(format!(
                        "rotator: account {idx} unavailable"
                    )));
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            PluginError::Plugin("rotator: all accounts exhausted".into())
        }))
    }

    async fn update(&self, handle: &NativeHandle, payload: &[u8]) -> Result<PutResult> {
        // Updates target a specific handle issued by a specific
        // account; we don't know which without metadata, so try each
        // until one returns success or NotFound.
        for (idx, acc) in self.accounts.iter().enumerate() {
            match acc.update(handle, payload).await {
                Ok(r) => {
                    self.record_use(idx);
                    return Ok(r);
                }
                Err(PluginError::NotFound(_)) => continue,
                Err(PluginError::NotSupported(_)) => {
                    return Err(PluginError::NotSupported(
                        "rotator: no account supports update".into(),
                    ));
                }
                Err(_) => continue,
            }
        }
        Err(PluginError::NotFound("rotator: no account had this handle".into()))
    }

    async fn get(&self, handle: &NativeHandle, range: Option<Range>) -> Result<Vec<u8>> {
        for acc in &self.accounts {
            match acc.get(handle, range).await {
                Ok(b) => return Ok(b),
                Err(PluginError::NotFound(_)) => continue,
                // Any other error: bubble up — we can't tell which
                // account would have served it.
                Err(e) => return Err(e),
            }
        }
        Err(PluginError::NotFound(
            "rotator: no account had this handle".into(),
        ))
    }

    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult> {
        for acc in &self.accounts {
            if let Ok(p) = acc.peek(handle).await {
                if p.exists {
                    return Ok(p);
                }
            }
        }
        Ok(PeekResult {
            exists: false,
            size: 0,
            mtime: Timestamp::from_string("rotator"),
            etag: None,
        })
    }

    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult> {
        let mut last = DeleteResult {
            outcome: DeleteOutcome::NotFound,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::Low,
            tombstone_clears_at: None,
        };
        for acc in &self.accounts {
            match acc.delete(handle).await {
                Ok(r) => match r.outcome {
                    DeleteOutcome::NotFound => last = r,
                    _ => return Ok(r),
                },
                Err(_) => continue,
            }
        }
        Ok(last)
    }

    async fn health(&self) -> Result<HealthReport> {
        let mut any_healthy = false;
        for acc in &self.accounts {
            if let Ok(r) = acc.health().await {
                if r.state == HealthState::Healthy {
                    any_healthy = true;
                    break;
                }
            }
        }
        Ok(HealthReport {
            state: if any_healthy {
                HealthState::Healthy
            } else {
                HealthState::Unhealthy
            },
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: true,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("rotator"),
            },
            latency: LatencyProfile::default(),
            score: if any_healthy {
                HealthScore::new(1.0)
            } else {
                HealthScore::new(0.0)
            },
        })
    }
}

fn sum_bucket(a: RateBucket, b: RateBucket) -> RateBucket {
    RateBucket::new(a.per_sec + b.per_sec, a.burst.saturating_add(b.burst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    use crate::RateLimitScope;

    struct MockAccount {
        name: &'static str,
        put_count: AtomicU32,
        rate_limited: std::sync::atomic::AtomicBool,
        fail: std::sync::atomic::AtomicBool,
        storage: Mutex<Vec<(Vec<u8>, Vec<u8>)>>, // (handle, bytes)
    }

    impl MockAccount {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                put_count: AtomicU32::new(0),
                rate_limited: std::sync::atomic::AtomicBool::new(false),
                fail: std::sync::atomic::AtomicBool::new(false),
                storage: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl PluginContract for MockAccount {
        fn rate_limit_profile(&self) -> RateLimitProfile {
            RateLimitProfile::unbounded()
        }
        async fn put(&self, payload: &[u8], _hint: &PutHint) -> Result<PutResult> {
            if self.rate_limited.load(Ordering::SeqCst) {
                return Err(PluginError::RateLimited {
                    retry_after: Duration::from_millis(10),
                    scope: RateLimitScope::Global,
                });
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(PluginError::Unavailable(self.name.into()));
            }
            let n = self.put_count.fetch_add(1, Ordering::SeqCst);
            let h = format!("{}-{n}", self.name).into_bytes();
            self.storage
                .lock()
                .unwrap()
                .push((h.clone(), payload.to_vec()));
            Ok(PutResult {
                handle: NativeHandle(h),
                handle_changed: true,
                prior_handle_state: None,
                stored_at: Timestamp::from_string("mock"),
                quota_reclaimed: QuotaReclaimed::Unknown,
                tombstone_clears_at: None,
            })
        }
        async fn get(&self, h: &NativeHandle, _r: Option<Range>) -> Result<Vec<u8>> {
            for (k, v) in self.storage.lock().unwrap().iter() {
                if k == &h.0 {
                    return Ok(v.clone());
                }
            }
            Err(PluginError::NotFound("not on this account".into()))
        }
        async fn peek(&self, _: &NativeHandle) -> Result<PeekResult> {
            Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("mock"),
                etag: None,
            })
        }
        async fn delete(&self, _: &NativeHandle) -> Result<DeleteResult> {
            Ok(DeleteResult {
                outcome: DeleteOutcome::NotSupported,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            })
        }
        async fn health(&self) -> Result<HealthReport> {
            Ok(HealthReport {
                state: HealthState::Healthy,
                quota: QuotaState {
                    total: None,
                    used: None,
                    untrusted: true,
                },
                rate_limit: RateLimitState {
                    remaining: u32::MAX,
                    reset_at: Timestamp::from_string("mock"),
                },
                latency: LatencyProfile::default(),
                score: HealthScore::new(1.0),
            })
        }
    }

    fn rotator(strategy: AccountStrategy, n: usize) -> (AccountRotator, Vec<Arc<MockAccount>>) {
        let names = ["a", "b", "c", "d", "e"];
        let accounts: Vec<Arc<MockAccount>> = (0..n).map(|i| MockAccount::new(names[i])).collect();
        let dyn_accounts: Vec<Arc<dyn PluginContract>> = accounts
            .iter()
            .map(|a| -> Arc<dyn PluginContract> { a.clone() })
            .collect();
        (AccountRotator::new(dyn_accounts, strategy), accounts)
    }

    #[tokio::test]
    async fn round_robin_distributes_evenly() {
        let (rot, accs) = rotator(AccountStrategy::RoundRobin, 3);
        for _ in 0..6 {
            rot.put(b"x", &PutHint::default()).await.unwrap();
        }
        for (i, a) in accs.iter().enumerate() {
            assert_eq!(
                a.put_count.load(Ordering::SeqCst),
                2,
                "account {i} got {} puts; expected 2",
                a.put_count.load(Ordering::SeqCst)
            );
        }
        assert_eq!(rot.usage_snapshot(), vec![2, 2, 2]);
    }

    /// Layer R8 baseline (ROUTING.md §12 R8).
    ///
    /// 3-account RoundRobin rotator. Saturate one account (rate-limit
    /// it). The next put MUST rotate to a healthy sibling
    /// transparently; total succeeds; the saturated account never
    /// sees an additional put.
    #[tokio::test]
    async fn r8_saturating_one_account_rotates_to_next() {
        let (rot, accs) = rotator(AccountStrategy::RoundRobin, 3);
        // Pre-warm: one put each to set the RR cursor at 3 → next picks
        // index 0, then 1, then 2 …
        for _ in 0..3 {
            rot.put(b"warm", &PutHint::default()).await.unwrap();
        }
        let warm_counts: Vec<u32> = accs
            .iter()
            .map(|a| a.put_count.load(Ordering::SeqCst))
            .collect();
        assert_eq!(warm_counts, vec![1, 1, 1]);

        // Saturate account 0.
        accs[0].rate_limited.store(true, Ordering::SeqCst);

        // Two more puts. RR would have picked 0 then 1; with 0
        // saturated each call advances past it to 1 / 2 respectively.
        rot.put(b"hot", &PutHint::default()).await.unwrap();
        rot.put(b"hot2", &PutHint::default()).await.unwrap();

        // Account 0's count is unchanged (it never accepted a put
        // post-saturation). Accounts 1 and 2 absorbed both extras.
        assert_eq!(
            accs[0].put_count.load(Ordering::SeqCst),
            1,
            "saturated account should not have served further puts"
        );
        let hot_total =
            accs[1].put_count.load(Ordering::SeqCst) + accs[2].put_count.load(Ordering::SeqCst);
        assert_eq!(hot_total, 1 + 1 + 2, "siblings absorbed both warm and hot puts");
    }

    #[tokio::test]
    async fn least_used_picks_minimum() {
        let (rot, accs) = rotator(AccountStrategy::LeastUsed, 3);
        // Force account 1 to be used twice via direct put.
        rot.put(b"a", &PutHint::default()).await.unwrap();
        rot.put(b"b", &PutHint::default()).await.unwrap();
        rot.put(b"c", &PutHint::default()).await.unwrap();
        // After three puts on a fresh LeastUsed pool, distribution
        // should be 1/1/1 (each pick advances the minimum).
        assert_eq!(
            (
                accs[0].put_count.load(Ordering::SeqCst),
                accs[1].put_count.load(Ordering::SeqCst),
                accs[2].put_count.load(Ordering::SeqCst),
            ),
            (1, 1, 1)
        );
    }

    #[tokio::test]
    async fn all_saturated_returns_unavailable() {
        let (rot, accs) = rotator(AccountStrategy::RoundRobin, 2);
        for a in &accs {
            a.rate_limited.store(true, Ordering::SeqCst);
        }
        let r = rot.put(b"x", &PutHint::default()).await;
        assert!(matches!(r, Err(PluginError::Unavailable(_))));
    }

    #[tokio::test]
    async fn get_falls_through_accounts_for_unknown_handle() {
        let (rot, _accs) = rotator(AccountStrategy::RoundRobin, 3);
        let put = rot
            .put(b"hello", &PutHint::default())
            .await
            .unwrap();
        // Read should succeed by trying each account in turn until
        // the writing account claims the handle.
        let bytes = rot.get(&put.handle, None).await.unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn merged_profile_sums_rate_budgets() {
        let (rot, _accs) = rotator(AccountStrategy::RoundRobin, 3);
        let p = rot.rate_limit_profile();
        // Three unbounded accounts → puts.per_sec = 30000 (= 3 * 10000).
        assert!(p.puts.per_sec >= 9_000.0);
        assert!(p.label.contains("rotator(3)"));
    }
}
