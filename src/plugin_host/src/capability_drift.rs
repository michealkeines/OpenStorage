//! Per-provider runtime capability drift detection.
//!
//! ROUTING.md §6.4. A plugin declares a `CapabilitySet` at registration
//! (Delete, RangeRead, AtomicReplace, …) but reality is squishier:
//!
//! - Pixeldrain announced support for anonymous PUT, then quietly
//!   tightened to API-key-required.
//! - Catbox advertises `delete` only with `userhash`; without one,
//!   delete returns `not_supported`.
//! - GitHub revokes a PAT mid-session; subsequent `delete` returns
//!   `auth_failure`.
//!
//! Without runtime detection the engine keeps issuing pointless calls
//! that cost rate-limit budget and surface user-visible errors. The
//! `CapabilityDriftDetector` watches every call's outcome class and,
//! after `threshold` consecutive `NotSupported` responses for an op,
//! flips the engine's *observed* capability set so callers route
//! accordingly.
//!
//! This is a runtime *observation*, not a permanent verdict — the
//! detector also clears the override on the first subsequent success
//! (the ToS may have changed back, or auth may have rotated). This
//! is the §2.A.9-style "capability_changed" event in lighter form;
//! manual user confirmation for capability *loss* (when reloading a
//! plugin over older state) is a deeper integration handled
//! elsewhere.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use os_types::{Capability, CapabilitySet, ProviderId};

use crate::rate_limit::Op;

#[derive(Debug, Clone, Copy)]
pub struct CapabilityDriftConfig {
    /// N consecutive `NotSupported` returns to flip the observed view.
    pub threshold: u32,
}

impl Default for CapabilityDriftConfig {
    fn default() -> Self {
        Self { threshold: 3 }
    }
}

#[derive(Debug, Clone, Default)]
struct OpDrift {
    consecutive_not_supported: u32,
    observed_unsupported: bool,
}

#[derive(Debug, Clone, Default)]
struct ProviderDrift {
    /// Per-op observation state. Only ops that have been observed at
    /// least once appear here.
    by_op: HashMap<Op, OpDrift>,
}

pub struct CapabilityDriftDetector {
    inner: RwLock<HashMap<ProviderId, ProviderDrift>>,
    cfg: CapabilityDriftConfig,
}

impl Default for CapabilityDriftDetector {
    fn default() -> Self {
        Self::with_config(CapabilityDriftConfig::default())
    }
}

impl CapabilityDriftDetector {
    pub fn with_config(cfg: CapabilityDriftConfig) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            cfg,
        }
    }

    /// Tally a `NotSupported`-classified outcome on `op`. Returns true
    /// iff this call flipped the observed-unsupported flag.
    pub fn observe_not_supported(&self, provider: ProviderId, op: Op) -> bool {
        let mut g = self.inner.write().expect("drift map");
        let entry = g.entry(provider).or_default();
        let op_state = entry.by_op.entry(op).or_default();
        op_state.consecutive_not_supported = op_state.consecutive_not_supported.saturating_add(1);
        if !op_state.observed_unsupported
            && op_state.consecutive_not_supported >= self.cfg.threshold
        {
            op_state.observed_unsupported = true;
            true
        } else {
            false
        }
    }

    /// Tally a successful op. A success on a previously-flipped op
    /// clears the override (capability appears to be back).
    pub fn observe_success(&self, provider: ProviderId, op: Op) {
        let mut g = self.inner.write().expect("drift map");
        let entry = g.entry(provider).or_default();
        let op_state = entry.by_op.entry(op).or_default();
        op_state.consecutive_not_supported = 0;
        op_state.observed_unsupported = false;
    }

    /// Has the detector flipped its view of `op` on `provider`? If
    /// `true`, callers SHOULD skip the call and route accordingly
    /// (Delete → register Shadow without invoking; Update → fall back
    /// to fresh put; etc.).
    pub fn is_observed_unsupported(&self, provider: ProviderId, op: Op) -> bool {
        let g = self.inner.read().expect("drift map");
        g.get(&provider)
            .and_then(|p| p.by_op.get(&op))
            .map(|s| s.observed_unsupported)
            .unwrap_or(false)
    }

    /// Apply observation to a declared `CapabilitySet`: returns the
    /// effective set with any observed-unsupported flags removed.
    /// Useful for callers that want to consult capabilities without
    /// per-op breakdown.
    pub fn effective(&self, provider: ProviderId, declared: &CapabilitySet) -> CapabilitySet {
        let mut out = declared.clone();
        if self.is_observed_unsupported(provider, Op::Delete) {
            out.flags.remove(&Capability::Delete);
        }
        if self.is_observed_unsupported(provider, Op::Peek) {
            out.flags.remove(&Capability::Peek);
        }
        // Note: there's no Op variant for Update; the slot pool reads
        // `update_capability` directly from `RateLimitProfile`. Drift
        // for Update is exposed via `is_observed_unsupported(_, Op::Put)`
        // when an `update()` call returns NotSupported (the recording
        // wrapper records both as Op::Put for breaker purposes — see
        // recording.rs).
        out
    }

    /// Snapshot for metrics / debugging.
    pub fn snapshot(&self) -> Vec<(ProviderId, Op, bool)> {
        let g = self.inner.read().expect("drift map");
        let mut out = Vec::new();
        for (pid, p) in g.iter() {
            for (op, s) in p.by_op.iter() {
                out.push((*pid, *op, s.observed_unsupported));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> ProviderId {
        ProviderId::new_v7()
    }

    #[test]
    fn unknown_provider_op_not_drifted() {
        let d = CapabilityDriftDetector::default();
        assert!(!d.is_observed_unsupported(pid(), Op::Delete));
    }

    #[test]
    fn flips_after_threshold_consecutive_not_supported() {
        let d = CapabilityDriftDetector::default(); // threshold=3
        let p = pid();
        assert!(!d.observe_not_supported(p, Op::Delete));
        assert!(!d.observe_not_supported(p, Op::Delete));
        // The 3rd flips.
        assert!(d.observe_not_supported(p, Op::Delete));
        assert!(d.is_observed_unsupported(p, Op::Delete));
    }

    #[test]
    fn success_clears_the_drift() {
        let d = CapabilityDriftDetector::default();
        let p = pid();
        for _ in 0..3 {
            d.observe_not_supported(p, Op::Delete);
        }
        assert!(d.is_observed_unsupported(p, Op::Delete));
        d.observe_success(p, Op::Delete);
        assert!(!d.is_observed_unsupported(p, Op::Delete));
    }

    #[test]
    fn intermittent_success_resets_consecutive_count() {
        let d = CapabilityDriftDetector::default();
        let p = pid();
        d.observe_not_supported(p, Op::Delete);
        d.observe_not_supported(p, Op::Delete);
        d.observe_success(p, Op::Delete);
        d.observe_not_supported(p, Op::Delete);
        d.observe_not_supported(p, Op::Delete);
        // Only 2 consecutive after the success → not drifted.
        assert!(!d.is_observed_unsupported(p, Op::Delete));
    }

    #[test]
    fn drift_is_per_op() {
        let d = CapabilityDriftDetector::default();
        let p = pid();
        for _ in 0..3 {
            d.observe_not_supported(p, Op::Delete);
        }
        assert!(d.is_observed_unsupported(p, Op::Delete));
        assert!(!d.is_observed_unsupported(p, Op::Get));
    }

    /// Layer R9 baseline (ROUTING.md §12 R9, integration form).
    ///
    /// A plugin advertises `Delete` capability but its `delete()`
    /// method returns `NotSupported`. The recording wrapper feeds
    /// every outcome to the drift detector. After `threshold` (=3)
    /// observations, the engine's effective capability set drops
    /// `Delete`, and `is_observed_unsupported(_, Op::Delete)` returns
    /// true.
    ///
    /// This proves the host-side plumbing — recording wrapper sees
    /// the inner's `NotSupported`, classifies it correctly, and
    /// invokes the detector. The downstream consumer (vfs/dispatcher
    /// short-circuiting future delete calls based on the override)
    /// is already correct: callers query
    /// `Host::capability_drift().is_observed_unsupported(...)` before
    /// invoking. The query path is unit-tested in this module; the
    /// recording integration is covered here.
    #[tokio::test]
    async fn r9_recording_wrapper_flips_delete_after_threshold_not_supported() {
        use crate::contract::{
            DeleteResult as DR, HealthReport, HealthState, PeekResult, PluginContract,
            PutResult,
        };
        use crate::host::HealthMonitor;
        use crate::recording::RecordingChunkPlugin;
        use crate::{
            AbuseSensor, CapabilityDriftDetector, CircuitBreaker, PluginError,
            Result as PluginResult,
        };
        use async_trait::async_trait;
        use os_entities::{NativeHandle, PutHint};
        use os_types::{
            CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile, QuotaReclaimed,
            QuotaState, Range, RateLimitState, Timestamp,
        };
        use std::sync::Arc;

        struct DeclaresDeleteButRefuses;
        #[async_trait]
        impl PluginContract for DeclaresDeleteButRefuses {
            async fn put(
                &self,
                _: &[u8],
                _: &PutHint,
            ) -> PluginResult<PutResult> {
                unreachable!()
            }
            async fn get(
                &self,
                _: &NativeHandle,
                _: Option<Range>,
            ) -> PluginResult<Vec<u8>> {
                unreachable!()
            }
            async fn peek(&self, _: &NativeHandle) -> PluginResult<PeekResult> {
                unreachable!()
            }
            async fn delete(&self, _: &NativeHandle) -> PluginResult<DR> {
                Err(PluginError::NotSupported(
                    "this provider does not honor delete".into(),
                ))
            }
            async fn health(&self) -> PluginResult<HealthReport> {
                Ok(HealthReport {
                    state: HealthState::Healthy,
                    quota: QuotaState {
                        total: None,
                        used: None,
                        untrusted: true,
                    },
                    rate_limit: RateLimitState {
                        remaining: u32::MAX,
                        reset_at: Timestamp::from_string("n/a"),
                    },
                    latency: LatencyProfile::default(),
                    score: HealthScore::new(1.0),
                })
            }
        }

        let pid = ProviderId::new_v7();
        let drift = Arc::new(CapabilityDriftDetector::default());
        let monitor = Arc::new(HealthMonitor::default());
        let breaker = Arc::new(CircuitBreaker::default());
        let abuse = Arc::new(AbuseSensor::default());
        let wrapped = RecordingChunkPlugin::new(
            Arc::new(DeclaresDeleteButRefuses),
            monitor,
            breaker,
            abuse,
            drift.clone(),
            pid,
        );

        // Pre-flip: drift detector hasn't observed anything.
        assert!(!drift.is_observed_unsupported(pid, Op::Delete));

        // Three NotSupported deletes → flip on the third.
        let h = NativeHandle(vec![0u8; 4]);
        for _ in 0..3 {
            let _ = wrapped.delete(&h).await;
        }

        assert!(drift.is_observed_unsupported(pid, Op::Delete));
        // And the per-op flip is targeted; Get is unaffected.
        assert!(!drift.is_observed_unsupported(pid, Op::Get));
    }

    #[test]
    fn effective_removes_drifted_delete_flag() {
        let d = CapabilityDriftDetector::default();
        let p = pid();
        let declared = CapabilitySet::default()
            .with(Capability::Put)
            .with(Capability::Get)
            .with(Capability::Delete);
        // Pre-drift: Delete is in effective.
        assert!(d.effective(p, &declared).has(Capability::Delete));
        for _ in 0..3 {
            d.observe_not_supported(p, Op::Delete);
        }
        let eff = d.effective(p, &declared);
        assert!(eff.has(Capability::Put));
        assert!(eff.has(Capability::Get));
        assert!(!eff.has(Capability::Delete));
    }
}
