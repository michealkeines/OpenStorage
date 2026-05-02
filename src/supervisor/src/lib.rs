//! os-supervisor — autonomous tick loops for repair, scrub, GC, lease
//! renewal, anti-entropy, and snapshot rotation.
//!
//! Why this layer exists: pre-rework the engine had endpoints
//! (`/v1/system/scrub`, `/v1/system/gc`, etc.) but no timer firing them.
//! `STATES_AND_FLOWS.md` F-HM-1 / F-HM-3 / F-HM-5 promised "timer; runs",
//! and that promise was vapor. This crate is the *one* place
//! background work originates from.
//!
//! Design rules:
//!
//! 1. **A single `Supervisor` owns every background tick loop** — no
//!    ad-hoc `tokio::spawn` scattered across services. Lifecycle is
//!    wired to a `CancellationToken` from `app/main.rs`.
//! 2. **Workers are pure `tick`** — each implements
//!    [`Worker::tick`]; they don't own their own loop. The supervisor
//!    schedules them with jittered interval + exponential back-off on
//!    error.
//! 3. **Tests drive `tick()` directly** — no need to wait for a real
//!    interval. Production uses [`Supervisor::run`] which spawns the
//!    `JoinSet`.
//!
//! Workers shipped here:
//! - [`Scrubber`] — F-HM-1 (samples shards, peeks for bit-rot, enqueues
//!   repairs). This is the Layer 1 baseline.
//!
//! Layer 2+ will add `LeaseRenewer`, `Gc`, `AntiEntropy`,
//! `SnapshotPusher`, `RepairDrainer`, `ShadowSweeper`, `HealthMonitor`.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use os_metadata::{ColumnFamily, Store};
use os_repair::{RepairScheduler, RepairSource, RepairTask};
use rand::seq::SliceRandom;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub use enforcer::HealthEnforcer;
pub use scrubber::Scrubber;

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("worker error: {worker}: {cause}")]
    Worker {
        worker: &'static str,
        cause: String,
    },
}

pub type Result<T> = std::result::Result<T, SupervisorError>;

/// One unit of background work. Implementors are pure: the supervisor
/// owns scheduling, jitter, back-off, and shutdown.
#[async_trait]
pub trait Worker: Send + Sync + 'static {
    /// Stable identifier used in tracing + metrics.
    fn name(&self) -> &'static str;

    /// Nominal cadence. The supervisor adds ±25% jitter so multiple
    /// workers don't synchronize.
    fn interval(&self) -> Duration;

    /// Do one unit of work. Should be idempotent and bounded — the
    /// supervisor will call this again next tick.
    async fn tick(&self) -> Result<()>;
}

/// Owns every background tick loop. Construct with workers, call
/// [`Supervisor::run`], hold the [`CancellationToken`] to drive shutdown.
pub struct Supervisor {
    workers: Vec<Arc<dyn Worker>>,
    cancel: CancellationToken,
}

impl Supervisor {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            workers: Vec::new(),
            cancel,
        }
    }

    pub fn with_worker(mut self, w: Arc<dyn Worker>) -> Self {
        self.workers.push(w);
        self
    }

    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Spawn every worker into a `JoinSet`. Returns a future that
    /// completes when all loops have observed cancellation.
    pub fn run(self) -> JoinSet<()> {
        let mut set = JoinSet::new();
        for w in self.workers {
            let cancel = self.cancel.clone();
            let name = w.name();
            set.spawn(async move {
                let mut backoff = Duration::from_millis(100);
                let max_backoff = Duration::from_secs(30);
                loop {
                    let interval = jittered(w.interval());
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            tracing::info!(worker = name, "supervisor cancelled");
                            return;
                        }
                        _ = tokio::time::sleep(interval) => {}
                    }
                    match w.tick().await {
                        Ok(()) => {
                            backoff = Duration::from_millis(100);
                        }
                        Err(e) => {
                            tracing::warn!(
                                worker = name,
                                error = %e,
                                backoff_ms = backoff.as_millis() as u64,
                                "supervisor tick failed"
                            );
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = tokio::time::sleep(backoff) => {}
                            }
                            backoff = (backoff * 2).min(max_backoff);
                        }
                    }
                }
            });
        }
        set
    }
}

fn jittered(base: Duration) -> Duration {
    use rand::Rng;
    let ms = base.as_millis() as u64;
    if ms == 0 {
        return base;
    }
    let span = ms / 4;
    let delta: i64 = rand::thread_rng().gen_range(-(span as i64)..=span as i64);
    let v = (ms as i64 + delta).max(1) as u64;
    Duration::from_millis(v)
}

mod scrubber {
    use super::*;
    use os_entities::Shard;
    use os_plugin_host::Host;
    use os_types::ChunkHash;

    /// F-HM-1 — sample-based shard health check. Each tick: pick up to
    /// `sample_size` shards, ask their plugin for `peek`, and enqueue a
    /// scrub-priority repair task on `peek.exists == false`. This catches
    /// the common bit-rot / silent-deletion case without requiring a
    /// persisted expected-hash on Shard (Layer 4 closure).
    pub struct Scrubber {
        store: Arc<Store>,
        host: Arc<Host>,
        repair: Arc<RepairScheduler>,
        events: Arc<os_events::EventBus>,
        interval: Duration,
        sample_size: usize,
    }

    impl Scrubber {
        pub fn new(
            store: Arc<Store>,
            host: Arc<Host>,
            repair: Arc<RepairScheduler>,
            events: Arc<os_events::EventBus>,
            interval: Duration,
        ) -> Self {
            Self {
                store,
                host,
                repair,
                events,
                interval,
                sample_size: 16,
            }
        }

        pub fn with_sample_size(mut self, n: usize) -> Self {
            self.sample_size = n;
            self
        }

        /// Inspect every shard in the store and return the chunk_hashes
        /// whose plugin reports `peek.exists == false`. Pure logic —
        /// extracted so tests can drive it without timers.
        pub async fn find_missing(&self) -> Result<Vec<ChunkHash>> {
            let mut shards: Vec<Shard> = Vec::new();
            for kv in self
                .store
                .backend()
                .scan_prefix(ColumnFamily::Shards, b"")
                .map_err(|e| SupervisorError::Worker {
                    worker: "scrubber",
                    cause: format!("scan: {e}"),
                })?
            {
                let (_k, v) = kv.map_err(|e| SupervisorError::Worker {
                    worker: "scrubber",
                    cause: format!("iter: {e}"),
                })?;
                if let Ok(s) = ciborium::from_reader::<Shard, _>(&v[..]) {
                    shards.push(s);
                }
            }
            shards.shuffle(&mut rand::thread_rng());
            let mut bad = Vec::new();
            for s in shards.into_iter().take(self.sample_size) {
                let provider = s.driver_id.value;
                let handle = &s.native_handle.value;
                let plugin = match self.host.get_chunk(provider) {
                    Ok(p) => p,
                    Err(_) => {
                        // Plugin no longer registered — treat as a
                        // health signal.
                        bad.push(s.chunk_hash);
                        continue;
                    }
                };
                match plugin.peek(handle).await {
                    Ok(peek) if peek.exists => {}
                    Ok(_) => bad.push(s.chunk_hash),
                    Err(_) => bad.push(s.chunk_hash),
                }
            }
            Ok(bad)
        }
    }

    #[async_trait]
    impl Worker for Scrubber {
        fn name(&self) -> &'static str {
            "scrubber"
        }
        fn interval(&self) -> Duration {
            self.interval
        }
        async fn tick(&self) -> Result<()> {
            let bad = self.find_missing().await?;
            for chunk_hash in bad {
                let _ = self.repair.enqueue(RepairTask {
                    chunk_hash,
                    priority: 5,
                    source: RepairSource::Scrub,
                    attempt: 0,
                });
                self.events
                    .publish(os_events::Event::new("repair.scheduled"));
            }
            Ok(())
        }
    }
}

mod enforcer {
    //! Layer 2 — observe `HealthMonitor` transitions and enqueue
    //! cleanup work. The real shedding (Shadow registration, chunk
    //! Degraded marker) lives in `os-api::run_repair`'s `PluginBan`
    //! arm — this worker just *notices* a Banned provider and asks the
    //! repair drainer to handle every chunk that touches it.

    use super::*;
    use os_entities::Shard;
    use os_plugin_host::Host;
    use os_types::ProviderId;

    pub struct HealthEnforcer {
        store: Arc<Store>,
        host: Arc<Host>,
        repair: Arc<RepairScheduler>,
        events: Arc<os_events::EventBus>,
        interval: Duration,
        seen_banned: std::sync::Mutex<std::collections::HashSet<ProviderId>>,
    }

    impl HealthEnforcer {
        pub fn new(
            store: Arc<Store>,
            host: Arc<Host>,
            repair: Arc<RepairScheduler>,
            events: Arc<os_events::EventBus>,
            interval: Duration,
        ) -> Self {
            Self {
                store,
                host,
                repair,
                events,
                interval,
                seen_banned: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
        }

        /// Pure logic — testable without timers. Returns the number of
        /// `RepairTask`s newly enqueued this tick.
        pub fn enforce(&self) -> Result<usize> {
            let snapshot = self.host.health_snapshot();
            let mut newly_banned: Vec<ProviderId> = Vec::new();
            {
                let mut seen = self.seen_banned.lock().expect("seen_banned mutex");
                for (pid, h) in &snapshot {
                    if h.is_banned() && !seen.contains(pid) {
                        newly_banned.push(*pid);
                        seen.insert(*pid);
                    }
                }
            }
            if newly_banned.is_empty() {
                return Ok(0);
            }
            self.events
                .publish(os_events::Event::new("plugin.health_changed"));
            // Walk Shards and enqueue PluginBan for every chunk touched
            // by a newly-banned provider.
            let mut affected = std::collections::HashSet::new();
            for kv in self
                .store
                .backend()
                .scan_prefix(ColumnFamily::Shards, b"")
                .map_err(|e| SupervisorError::Worker {
                    worker: "health_enforcer",
                    cause: format!("scan: {e}"),
                })?
            {
                let (_k, v) = kv.map_err(|e| SupervisorError::Worker {
                    worker: "health_enforcer",
                    cause: format!("iter: {e}"),
                })?;
                if let Ok(s) = ciborium::from_reader::<Shard, _>(&v[..]) {
                    if newly_banned.contains(&s.driver_id.value) {
                        affected.insert(s.chunk_hash);
                    }
                }
            }
            let mut enqueued = 0;
            for chunk_hash in affected {
                if self
                    .repair
                    .enqueue(RepairTask {
                        chunk_hash,
                        priority: 1, // higher than scrub; lower than read-repair
                        source: RepairSource::PluginBan,
                        attempt: 0,
                    })
                    .is_ok()
                {
                    enqueued += 1;
                }
            }
            Ok(enqueued)
        }
    }

    #[async_trait]
    impl Worker for HealthEnforcer {
        fn name(&self) -> &'static str {
            "health_enforcer"
        }
        fn interval(&self) -> Duration {
            self.interval
        }
        async fn tick(&self) -> Result<()> {
            let _ = self.enforce()?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingWorker {
        n: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait]
    impl Worker for CountingWorker {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn interval(&self) -> Duration {
            Duration::from_millis(20)
        }
        async fn tick(&self) -> Result<()> {
            self.n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervisor_ticks_workers_until_cancelled() {
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let w = Arc::new(CountingWorker { n: n.clone() });
        let cancel = CancellationToken::new();
        let cancel_for_drop = cancel.clone();
        let sup = Supervisor::new(cancel).with_worker(w);
        let mut set = sup.run();
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel_for_drop.cancel();
        while set.join_next().await.is_some() {}
        // ≥ 2 ticks within 200ms with a 20ms-jittered interval is a
        // safe lower bound that doesn't flake under CI variance.
        assert!(
            n.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            "worker ticked {} times",
            n.load(std::sync::atomic::Ordering::Relaxed)
        );
    }
}
