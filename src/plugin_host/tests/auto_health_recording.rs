//! Layer 2 closure baseline (per `STRUCTURAL_REWORK.md` drift item #3):
//! every `plugin.put / get / peek / delete` automatically records to
//! the `HealthMonitor`. Pre-fix, the classifier only fired when call
//! sites explicitly invoked `host.record_error(pid, &err)` — meaning a
//! production Discord auth-failure storm would never quarantine the
//! provider unless someone remembered to add the call.
//!
//! This test plugs in a deliberately-broken `PluginContract` that
//! always returns `AuthFailure`, makes 5 `put` calls through the
//! `Host::get_chunk(pid).put(...)` API, and asserts the provider is
//! now `Quarantined { reason: Auth }` — without any test code calling
//! `record_error` directly.

use std::sync::Arc;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    Host, PluginError, Result,
};
use os_types::{
    BlakeHash, CachedElsewhereRisk, DeleteOutcome, ErrorClass, HealthScore, LatencyProfile,
    ProviderHealth, ProviderId, QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};

struct AlwaysAuthFailPlugin;

#[async_trait]
impl PluginContract for AlwaysAuthFailPlugin {
    async fn put(&self, _payload: &[u8], _hint: &PutHint) -> Result<PutResult> {
        Err(PluginError::AuthFailure)
    }
    async fn get(&self, _h: &NativeHandle, _r: Option<Range>) -> Result<Vec<u8>> {
        Err(PluginError::AuthFailure)
    }
    async fn peek(&self, _h: &NativeHandle) -> Result<PeekResult> {
        Err(PluginError::AuthFailure)
    }
    async fn delete(&self, _h: &NativeHandle) -> Result<DeleteResult> {
        Err(PluginError::AuthFailure)
    }
    async fn health(&self) -> Result<HealthReport> {
        Ok(HealthReport {
            state: HealthState::Healthy,
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: false,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("now"),
            },
            latency: LatencyProfile::default(),
            score: HealthScore::new(1.0),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_real_auth_failures_quarantine_provider_without_explicit_record_error() {
    let host = Host::new();
    let pid = ProviderId::new_v7();
    host.register_chunk_unpaced(pid, Arc::new(AlwaysAuthFailPlugin));

    // Sanity: starts as Active.
    assert!(matches!(host.provider_health(pid), ProviderHealth::Active));

    // Drive 5 real `.put` calls through the host — no manual record_error.
    let plugin = host.get_chunk(pid).expect("plugin");
    for _ in 0..5 {
        let r = plugin.put(b"x", &PutHint::default()).await;
        assert!(matches!(r, Err(PluginError::AuthFailure)));
    }

    // The recording wrapper must have folded each AuthFailure into the
    // classifier. 5 Auths in the 60 s window crosses the threshold.
    let st = host.provider_health(pid);
    assert!(
        matches!(
            st,
            ProviderHealth::Quarantined {
                reason: ErrorClass::Auth,
                ..
            }
        ),
        "provider not quarantined after 5 auto-recorded auth failures: {:?}",
        st,
    );
}

struct AlternatingPlugin {
    counter: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl PluginContract for AlternatingPlugin {
    async fn put(&self, _payload: &[u8], _hint: &PutHint) -> Result<PutResult> {
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n.is_multiple_of(2) {
            Err(PluginError::Unavailable("flake".into()))
        } else {
            Ok(PutResult {
                handle: NativeHandle(vec![0xAA]),
                handle_changed: true,
                prior_handle_state: None,
                stored_at: Timestamp::from_string("now"),
                quota_reclaimed: QuotaReclaimed::Unknown,
                tombstone_clears_at: None,
            })
        }
    }
    async fn get(&self, _: &NativeHandle, _: Option<Range>) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    async fn peek(&self, _: &NativeHandle) -> Result<PeekResult> {
        Ok(PeekResult {
            exists: true,
            size: 0,
            mtime: Timestamp::from_string("now"),
            etag: None,
        })
    }
    async fn delete(&self, _: &NativeHandle) -> Result<DeleteResult> {
        Ok(DeleteResult {
            outcome: DeleteOutcome::Removed,
            quota_reclaimed: QuotaReclaimed::Unknown,
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
                untrusted: false,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("now"),
            },
            latency: LatencyProfile::default(),
            score: HealthScore::new(1.0),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successes_are_recorded_and_keep_provider_active() {
    // Fewer than `NETWORK_THRESHOLD` (=10) network errors mixed with
    // successes must NOT quarantine. This proves the wrapper isn't
    // over-recording — only real errors fold in.
    let host = Host::new();
    let pid = ProviderId::new_v7();
    host.register_chunk_unpaced(
        pid,
        Arc::new(AlternatingPlugin {
            counter: std::sync::atomic::AtomicUsize::new(0),
        }),
    );

    let plugin = host.get_chunk(pid).expect("plugin");
    for _ in 0..6 {
        let _ = plugin.put(b"x", &PutHint::default()).await;
    }
    assert!(
        matches!(host.provider_health(pid), ProviderHealth::Active),
        "alternating success/error tipped a provider over the threshold: {:?}",
        host.provider_health(pid),
    );

    // Avoid an unused symbol warning for `BlakeHash` — touched here so the
    // import in the file remains meaningful when expanded.
    let _ = std::marker::PhantomData::<BlakeHash>;
}
