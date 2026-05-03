//! Plugin host: registry of `ProviderId → plugin instance + middleware`.
//!
//! Also tracks the engine-maintained `ProviderHealth` for every
//! registered provider via [`HealthMonitor`] (Layer 2 of
//! `STRUCTURAL_REWORK.md`). Placement consults this state; repair workers
//! react when a provider transitions to `Banned`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use os_types::{ErrorClass, ProviderHealth, ProviderId, Timestamp};

use crate::contract::{PluginContract, VaultPluginContract};
use crate::rate_limit::{MiddlewarePolicy, RateLimitConfig, RateLimitMiddleware};
use crate::{PluginError, Result};

pub struct Host {
    chunk_plugins: RwLock<HashMap<ProviderId, ChunkEntry>>,
    vault_plugins: RwLock<HashMap<ProviderId, Arc<dyn VaultPluginContract>>>,
    /// Shared so the per-provider `RecordingChunkPlugin` /
    /// `RecordingVaultPlugin` wrappers can feed the same classifier
    /// without holding a back-reference to the whole `Host`.
    health: Arc<HealthMonitor>,
}

#[derive(Clone)]
struct ChunkEntry {
    /// What callers see — already wrapped in middleware when registered
    /// through `register_chunk_paced`.
    plugin: Arc<dyn PluginContract>,
    /// Concrete handle on the middleware so the dispatcher can read
    /// per-provider capacity / cooldown without paying a downcast.
    middleware: Option<Arc<RateLimitMiddleware>>,
}

impl Host {
    pub fn new() -> Self {
        Self {
            chunk_plugins: RwLock::new(HashMap::new()),
            vault_plugins: RwLock::new(HashMap::new()),
            health: Arc::new(HealthMonitor::default()),
        }
    }

    // ── Layer 2 — provider-health surface ────────────────────────────────

    /// Classify and record an error against `provider_id`. Caller passes
    /// the `PluginError` they observed; we map it to an `ErrorClass` and
    /// fold it into the sliding-window classifier. Any state transition
    /// (Active→Quarantined, Quarantined→Banned, etc.) takes effect on
    /// the next [`provider_health`] read.
    pub fn record_error(&self, provider_id: ProviderId, err: &PluginError) {
        self.health.record(provider_id, classify_error(err));
    }

    /// Force-classify an error (used by callers who already know the
    /// class — e.g., the scrubber treating a missing peek as Corruption,
    /// or a chunk-AEAD-fail in the read path).
    pub fn record_class(&self, provider_id: ProviderId, class: ErrorClass) {
        self.health.record(provider_id, class);
    }

    /// Mark a successful interaction. Successes age out errors so a
    /// transient blip clears.
    pub fn record_success(&self, provider_id: ProviderId) {
        self.health.note_success(provider_id);
    }

    /// Current engine-side state for `provider_id`. Defaults to `Active`
    /// when nothing has been observed.
    pub fn provider_health(&self, provider_id: ProviderId) -> ProviderHealth {
        self.health.state(provider_id)
    }

    /// Test-only: directly force a state. Production code uses
    /// `record_error` / `record_class` / `record_success`.
    pub fn force_health(&self, provider_id: ProviderId, state: ProviderHealth) {
        self.health.force(provider_id, state);
    }

    /// Snapshot of every provider's current health. Used by the
    /// `HealthEnforcer` worker to detect newly-Banned providers.
    pub fn health_snapshot(&self) -> Vec<(ProviderId, ProviderHealth)> {
        self.health.snapshot()
    }

    // ── Layer 3 — CAS-tier surface ───────────────────────────────────────

    /// CAS tier declared by the registered vault plugin for `provider_id`,
    /// or `None` if no vault plugin is registered for that id.
    pub fn vault_cas_tier(&self, provider_id: ProviderId) -> Option<os_types::CasTier> {
        self.vault_plugins
            .read()
            .expect("host registry")
            .get(&provider_id)
            .map(|p| p.cas_tier())
    }

    /// Vault providers filtered to those meeting at least `tier`. Used by
    /// snapshot-push and lease coordinators to refuse weak-CAS backends
    /// for sole-source coordination roles.
    pub fn vault_providers_at_least(&self, tier: os_types::CasTier) -> Vec<ProviderId> {
        let g = self.vault_plugins.read().expect("host registry");
        g.iter()
            .filter(|(_, p)| p.cas_tier().is_at_least(tier))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Register a chunk plugin. The host calls `plugin.rate_limit_profile()`
    /// to learn the backend's limits, then wraps the plugin in
    /// `RateLimitMiddleware` automatically. Plugin authors don't have to
    /// know anything about middleware — they just declare their profile.
    pub fn register_chunk(&self, id: ProviderId, plugin: Arc<dyn PluginContract>) {
        self.register_chunk_with_policy(id, plugin, MiddlewarePolicy::default());
    }

    /// Same as `register_chunk` but with an explicit host policy override
    /// (max-transient-attempts, backoff bounds, jitter).
    pub fn register_chunk_with_policy(
        &self,
        id: ProviderId,
        plugin: Arc<dyn PluginContract>,
        policy: MiddlewarePolicy,
    ) {
        let profile = plugin.rate_limit_profile();
        let cfg = RateLimitConfig::from_profile(&profile, &policy);
        let label = format!("chunk:{}:{}", profile.label, id);
        let mw = Arc::new(RateLimitMiddleware::new(plugin, cfg).with_label(label));
        // Outer wrapper auto-records every put/get/peek/delete to the
        // shared `HealthMonitor` (Layer 2 closure).
        let wrapped: Arc<dyn PluginContract> = Arc::new(
            crate::recording::RecordingChunkPlugin::new(
                mw.clone(),
                self.health.clone(),
                id,
            ),
        );
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin: wrapped,
                middleware: Some(mw),
            },
        );
    }

    /// Register without any pacing. Test fixtures only — production paths
    /// always go through `register_chunk` so profiles are honored.
    pub fn register_chunk_unpaced(&self, id: ProviderId, plugin: Arc<dyn PluginContract>) {
        let wrapped: Arc<dyn PluginContract> = Arc::new(
            crate::recording::RecordingChunkPlugin::new(plugin, self.health.clone(), id),
        );
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin: wrapped,
                middleware: None,
            },
        );
    }

    /// Register with a hand-crafted `RateLimitConfig`, bypassing the
    /// plugin's profile. Test fixtures only — for production, the plugin's
    /// `rate_limit_profile()` is the source of truth.
    pub fn register_chunk_with_config(
        &self,
        id: ProviderId,
        plugin: Arc<dyn PluginContract>,
        cfg: RateLimitConfig,
    ) {
        let mw = Arc::new(
            RateLimitMiddleware::new(plugin, cfg).with_label(format!("chunk:{id}")),
        );
        let wrapped: Arc<dyn PluginContract> = Arc::new(
            crate::recording::RecordingChunkPlugin::new(
                mw.clone(),
                self.health.clone(),
                id,
            ),
        );
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin: wrapped,
                middleware: Some(mw),
            },
        );
    }

    pub fn register_vault(&self, id: ProviderId, plugin: Arc<dyn VaultPluginContract>) {
        let wrapped: Arc<dyn VaultPluginContract> = Arc::new(
            crate::recording::RecordingVaultPlugin::new(plugin, self.health.clone(), id),
        );
        self.vault_plugins
            .write()
            .expect("host registry")
            .insert(id, wrapped);
    }

    pub fn get_chunk(&self, id: ProviderId) -> Result<Arc<dyn PluginContract>> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .map(|e| e.plugin.clone())
            .ok_or_else(|| PluginError::NotFound(format!("chunk plugin {id}")))
    }

    /// Returns the middleware wrapping `id`, if any. The dispatcher uses
    /// this to query capacity without locking the bucket from outside.
    pub fn middleware_for(&self, id: ProviderId) -> Option<Arc<RateLimitMiddleware>> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .and_then(|e| e.middleware.clone())
    }

    pub fn get_vault(&self, id: ProviderId) -> Result<Arc<dyn VaultPluginContract>> {
        self.vault_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("vault plugin {id}")))
    }

    pub fn list_chunk(&self) -> Vec<ProviderId> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .keys()
            .copied()
            .collect()
    }

    pub fn list_vault(&self) -> Vec<ProviderId> {
        self.vault_plugins
            .read()
            .expect("host registry")
            .keys()
            .copied()
            .collect()
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Layer 2 — provider health classifier.
// ──────────────────────────────────────────────────────────────────────────

/// Map a raw [`PluginError`] to its engine-side error class. The
/// classifier consumes these to decide whether a provider should be
/// Quarantined or Banned.
pub fn classify_error(err: &PluginError) -> ErrorClass {
    match err {
        PluginError::AuthFailure => ErrorClass::Auth,
        PluginError::RateLimited { .. } => ErrorClass::RateLimit,
        PluginError::Io(_) | PluginError::Unavailable(_) => ErrorClass::Network,
        PluginError::NotFound(_) => ErrorClass::NotFound,
        PluginError::IdempotencyViolation => ErrorClass::Other,
        PluginError::NotSupported(_) | PluginError::Plugin(_) => ErrorClass::Other,
    }
}

/// Per-provider sliding-window error history. Drives the
/// [`ProviderHealth`] state machine.
///
/// Thresholds (intentionally hard-coded — these are policy, not
/// configuration; if we want to surface knobs they go in a config struct):
/// - 5 `Auth` errors in 60 s → `Quarantined { reason: Auth }`
/// - 10 `Network` errors in 60 s → `Quarantined { reason: Network }`
/// - 5 `Corruption` events ever → `Quarantined { reason: Corruption }`
/// - Quarantined for ≥ 5 min with no successes → `Banned`
/// - 3 successes after Quarantined returns to `Active` (network/rate-limit
///   reasons only — Auth and Corruption don't auto-clear)
pub struct HealthMonitor {
    inner: RwLock<HashMap<ProviderId, ProviderState>>,
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct ProviderState {
    /// Recent error class instances with their wall-clock instant.
    recent: VecDeque<(std::time::Instant, ErrorClass)>,
    /// Cumulative corruption events (never expires — once we see
    /// silent data loss we don't forget).
    total_corruption: u32,
    /// Successes counted while in a transient quarantine; clears the
    /// state once high enough.
    successes_since_quarantine: u32,
    /// Current resolved health.
    current: ProviderHealth,
    /// Wall-clock when the provider entered the *current* state.
    state_since: Option<std::time::Instant>,
}

const WINDOW: Duration = Duration::from_secs(60);
const AUTH_THRESHOLD: usize = 5;
const NETWORK_THRESHOLD: usize = 10;
const CORRUPTION_THRESHOLD: u32 = 5;
const QUARANTINE_TO_BAN: Duration = Duration::from_secs(5 * 60);
const SUCCESSES_TO_CLEAR: u32 = 3;

impl HealthMonitor {
    pub fn record(&self, provider_id: ProviderId, class: ErrorClass) {
        let now = std::time::Instant::now();
        let mut g = self.inner.write().expect("health monitor");
        let st = g.entry(provider_id).or_default();
        st.recent.push_back((now, class));
        // Drop entries outside the window.
        while st
            .recent
            .front()
            .map(|(t, _)| now.duration_since(*t) > WINDOW)
            .unwrap_or(false)
        {
            st.recent.pop_front();
        }
        if matches!(class, ErrorClass::Corruption) {
            st.total_corruption = st.total_corruption.saturating_add(1);
        }
        // Re-evaluate.
        Self::evaluate(st, now);
    }

    pub fn note_success(&self, provider_id: ProviderId) {
        let now = std::time::Instant::now();
        let mut g = self.inner.write().expect("health monitor");
        let st = g.entry(provider_id).or_default();
        st.successes_since_quarantine = st.successes_since_quarantine.saturating_add(1);
        Self::evaluate(st, now);
    }

    pub fn force(&self, provider_id: ProviderId, state: ProviderHealth) {
        let mut g = self.inner.write().expect("health monitor");
        let st = g.entry(provider_id).or_default();
        st.current = state;
        st.state_since = Some(std::time::Instant::now());
    }

    pub fn state(&self, provider_id: ProviderId) -> ProviderHealth {
        let now = std::time::Instant::now();
        let mut g = self.inner.write().expect("health monitor");
        let st = g.entry(provider_id).or_default();
        Self::evaluate(st, now);
        st.current.clone()
    }

    pub fn snapshot(&self) -> Vec<(ProviderId, ProviderHealth)> {
        let now = std::time::Instant::now();
        let mut g = self.inner.write().expect("health monitor");
        let mut out = Vec::with_capacity(g.len());
        for (id, st) in g.iter_mut() {
            Self::evaluate(st, now);
            out.push((*id, st.current.clone()));
        }
        out
    }

    fn evaluate(st: &mut ProviderState, now: std::time::Instant) {
        // Drop stale window entries.
        while st
            .recent
            .front()
            .map(|(t, _)| now.duration_since(*t) > WINDOW)
            .unwrap_or(false)
        {
            st.recent.pop_front();
        }
        let auth_count = st
            .recent
            .iter()
            .filter(|(_, c)| matches!(c, ErrorClass::Auth))
            .count();
        let net_count = st
            .recent
            .iter()
            .filter(|(_, c)| matches!(c, ErrorClass::Network))
            .count();

        let next: ProviderHealth = match &st.current {
            ProviderHealth::Active => {
                if auth_count >= AUTH_THRESHOLD {
                    ProviderHealth::Quarantined {
                        reason: ErrorClass::Auth,
                        since: Timestamp::from_string("now"),
                    }
                } else if st.total_corruption >= CORRUPTION_THRESHOLD {
                    ProviderHealth::Quarantined {
                        reason: ErrorClass::Corruption,
                        since: Timestamp::from_string("now"),
                    }
                } else if net_count >= NETWORK_THRESHOLD {
                    ProviderHealth::Quarantined {
                        reason: ErrorClass::Network,
                        since: Timestamp::from_string("now"),
                    }
                } else {
                    ProviderHealth::Active
                }
            }
            ProviderHealth::Quarantined { reason, .. } => {
                let since = st.state_since.unwrap_or(now);
                let elapsed = now.duration_since(since);
                if elapsed >= QUARANTINE_TO_BAN {
                    // Long-quarantined → Banned (data-bearing failure).
                    ProviderHealth::Banned {
                        since: Timestamp::from_string("now"),
                    }
                } else if matches!(reason, ErrorClass::Network | ErrorClass::RateLimit)
                    && st.successes_since_quarantine >= SUCCESSES_TO_CLEAR
                {
                    // Transient → recover.
                    st.successes_since_quarantine = 0;
                    ProviderHealth::Active
                } else {
                    st.current.clone()
                }
            }
            ProviderHealth::Banned { .. } => st.current.clone(),
        };
        if next != st.current {
            st.current = next;
            st.state_since = Some(now);
        } else if st.state_since.is_none() {
            st.state_since = Some(now);
        }
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn five_auth_errors_quarantine_provider() {
        let h = HealthMonitor::default();
        let id = ProviderId::new_v7();
        for _ in 0..5 {
            h.record(id, ErrorClass::Auth);
        }
        assert!(matches!(
            h.state(id),
            ProviderHealth::Quarantined { reason: ErrorClass::Auth, .. }
        ));
    }

    #[test]
    fn isolated_auth_does_not_quarantine() {
        let h = HealthMonitor::default();
        let id = ProviderId::new_v7();
        h.record(id, ErrorClass::Auth);
        h.record(id, ErrorClass::Auth);
        assert_eq!(h.state(id), ProviderHealth::Active);
    }

    #[test]
    fn force_state_sticks() {
        let h = HealthMonitor::default();
        let id = ProviderId::new_v7();
        h.force(
            id,
            ProviderHealth::Banned {
                since: Timestamp::from_string("now"),
            },
        );
        assert!(h.state(id).is_banned());
    }

    #[test]
    fn classify_known_errors() {
        assert_eq!(classify_error(&PluginError::AuthFailure), ErrorClass::Auth);
        assert_eq!(
            classify_error(&PluginError::Unavailable("x".into())),
            ErrorClass::Network
        );
        assert_eq!(
            classify_error(&PluginError::NotFound("x".into())),
            ErrorClass::NotFound
        );
    }
}
