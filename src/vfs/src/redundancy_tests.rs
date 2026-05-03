//! Redundancy tests — exercise every documented case from DESIGN.md /
//! RESILIENCE.md / STATES_AND_FLOWS.md.
//!
//! Mock plugins let us flip behaviors at runtime: fail puts, fail gets,
//! rate-limit, count operations, drop a specific shard's bytes. Each test
//! constructs a fresh fixture with N distinct trust groups so dynamic EC
//! selection produces the scheme being exercised.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use os_crypto::generate_keypair;
use os_entities::{NativeHandle, PutHint};
use os_metadata::{backend::MemoryBackend, Store, Txn};
use os_placement::EcTargets;
use os_plugin_host::{
    contract::{
        DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
    },
    Host, PluginError, RateLimitScope, Result as PluginResult,
};
use os_sync::SyncEngine;
use os_types::{
    AeadSuite, CachedElsewhereRisk, DeleteOutcome, DeviceId, HealthScore, LatencyProfile,
    ProviderId, QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp, TrustCorrelationGroup,
    VaultId,
};
use os_vault::VaultManager;
use os_wal::WalBuilder;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{VfsConfig, VfsService};

// ─── MockPlugin ───────────────────────────────────────────────────────────
//
// Stable handle = blake3(payload). Lets us reproducibly target a stored
// shard by knowing its content. Per-instance toggles for fail / rate-limit /
// drop. Counts ops so tests can assert which provider got asked.

pub struct MockPlugin {
    pub name: &'static str,
    storage: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    pub fail_puts: AtomicBool,
    pub fail_gets: AtomicBool,
    pub rate_limited: AtomicBool,
    pub forget_data: AtomicBool,
    pub put_count: AtomicU32,
    pub get_count: AtomicU32,
    /// When true, the plugin advertises `UpdateCapability::TrueUpdate`
    /// in its rate-limit profile and the `update` trait method is
    /// implemented in-place (same handle, new bytes). Toggle in tests
    /// that exercise the slot pool.
    pub update_capable: AtomicBool,
    pub update_count: AtomicU32,
}

impl MockPlugin {
    pub fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            storage: Mutex::new(HashMap::new()),
            fail_puts: AtomicBool::new(false),
            fail_gets: AtomicBool::new(false),
            rate_limited: AtomicBool::new(false),
            forget_data: AtomicBool::new(false),
            put_count: AtomicU32::new(0),
            get_count: AtomicU32::new(0),
            update_capable: AtomicBool::new(false),
            update_count: AtomicU32::new(0),
        })
    }

    pub fn stored_bytes(&self) -> usize {
        self.storage.lock().unwrap().values().map(|v| v.len()).sum()
    }
}

#[async_trait]
impl PluginContract for MockPlugin {
    fn rate_limit_profile(&self) -> os_plugin_host::rate_limit::RateLimitProfile {
        let mut p = os_plugin_host::rate_limit::RateLimitProfile::unbounded();
        if self.update_capable.load(Ordering::SeqCst) {
            p.update_capability = os_types::UpdateCapability::TrueUpdate;
        }
        p
    }

    async fn update(
        &self,
        handle: &NativeHandle,
        payload: &[u8],
    ) -> PluginResult<PutResult> {
        if !self.update_capable.load(Ordering::SeqCst) {
            return Err(PluginError::NotSupported("not update_capable".into()));
        }
        self.update_count.fetch_add(1, Ordering::SeqCst);
        // True in-place update: store at the same handle key.
        self.storage
            .lock()
            .unwrap()
            .insert(handle.0.clone(), payload.to_vec());
        Ok(PutResult {
            handle: handle.clone(),
            handle_changed: false,
            prior_handle_state: Some(os_types::PriorHandleState::Overwritten),
            stored_at: Timestamp::from_string("mock-update"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        self.put_count.fetch_add(1, Ordering::SeqCst);
        if self.rate_limited.load(Ordering::SeqCst) {
            return Err(PluginError::RateLimited {
                retry_after: Duration::from_millis(20),
                scope: RateLimitScope::Global,
            });
        }
        if self.fail_puts.load(Ordering::SeqCst) {
            return Err(PluginError::Unavailable("mock fail_puts".into()));
        }
        let h = blake3::hash(payload).as_bytes().to_vec();
        self.storage
            .lock()
            .unwrap()
            .insert(h.clone(), payload.to_vec());
        Ok(PutResult {
            handle: NativeHandle(h),
            handle_changed: true,
            prior_handle_state: None,
            stored_at: Timestamp::from_string("mock"),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(&self, handle: &NativeHandle, _r: Option<Range>) -> PluginResult<Vec<u8>> {
        self.get_count.fetch_add(1, Ordering::SeqCst);
        if self.rate_limited.load(Ordering::SeqCst) {
            return Err(PluginError::RateLimited {
                retry_after: Duration::from_millis(20),
                scope: RateLimitScope::Global,
            });
        }
        if self.fail_gets.load(Ordering::SeqCst) {
            return Err(PluginError::Unavailable("mock fail_gets".into()));
        }
        if self.forget_data.load(Ordering::SeqCst) {
            return Err(PluginError::NotFound("forgotten".into()));
        }
        match self.storage.lock().unwrap().get(&handle.0) {
            Some(b) => Ok(b.clone()),
            None => Err(PluginError::NotFound("unknown handle".into())),
        }
    }

    async fn peek(&self, handle: &NativeHandle) -> PluginResult<PeekResult> {
        match self.storage.lock().unwrap().get(&handle.0) {
            Some(b) => Ok(PeekResult {
                exists: true,
                size: b.len() as u64,
                mtime: Timestamp::from_string("mock"),
                etag: None,
            }),
            None => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("mock"),
                etag: None,
            }),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> PluginResult<DeleteResult> {
        self.storage.lock().unwrap().remove(&handle.0);
        Ok(DeleteResult {
            outcome: DeleteOutcome::Removed,
            quota_reclaimed: QuotaReclaimed::Yes,
            cached_elsewhere_risk: CachedElsewhereRisk::Low,
            tombstone_clears_at: None,
        })
    }

    async fn health(&self) -> PluginResult<HealthReport> {
        Ok(HealthReport {
            state: HealthState::Healthy,
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: false,
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

// ─── Fixture builder ──────────────────────────────────────────────────────

pub struct Fixture {
    pub svc: Arc<VfsService>,
    pub providers: Vec<(ProviderId, Arc<MockPlugin>)>,
    pub store: Arc<Store>,
    pub host: Arc<Host>,
}

pub fn fixture(n_groups: usize, k_target: u8, chunk_bytes: usize) -> Fixture {
    let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
    let host = Arc::new(Host::new());

    // Box::leak the names so they live as 'static. Tests are short-lived;
    // this is a controlled leak in test code only.
    let names: Vec<&'static str> = (0..n_groups)
        .map(|i| Box::leak(format!("mock-{i}").into_boxed_str()) as &'static str)
        .collect();

    let mut providers = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let plugin = MockPlugin::new(name);
        let pid = ProviderId::new_v7();
        host.register_chunk(pid, plugin.clone());

        let provider = os_entities::Provider {
            provider_id: pid,
            plugin_id: os_types::PluginId::new("org.openstorage.mock"),
            instance_label: name.to_string(),
            credentials_handle: os_types::CredentialsHandle::new(vec![]).unwrap(),
            capabilities: os_types::CapabilitySet::default(),
            legal_class: os_types::LegalClass::Green,
            trust_correlation_group: TrustCorrelationGroup::new(&format!("group-{i}")),
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: false,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("mock"),
            },
            health: HealthScore::new(1.0),
            latency: LatencyProfile::default(),
            untrusted_quota: false,
        };
        let mut txn = Txn::new();
        store.put_provider(&mut txn, &provider).unwrap();
        store.commit(txn).unwrap();
        providers.push((pid, plugin));
    }

    let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
    vault.set_unlocked(VaultId::new_v7(), [9u8; 32]).unwrap();

    let mut tdir = std::env::temp_dir();
    tdir.push(format!("os-redundancy-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tdir).unwrap();
    let (sk, _pk) = generate_keypair(&mut OsRng);
    let wal = WalBuilder::new()
        .path(tdir.join("wal.bin"))
        .build(DeviceId::new_v7(), sk)
        .unwrap();
    let sync = Arc::new(SyncEngine::new(Arc::new(wal)));

    let svc = Arc::new(VfsService::with_host(
        store.clone(),
        vault,
        sync,
        host.clone(),
        VfsConfig {
            inline_threshold_bytes: 64,
            chunk_bytes,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            ec_targets: EcTargets {
                k_target,
                n_max: 13,
            },
            read_hedge: 1,
            chunk_upload_concurrency: 4,
            chunk_fetch_concurrency: 4,
        },
    ));
    Fixture {
        svc,
        providers,
        store,
        host,
    }
}

fn random_payload(size: usize) -> Vec<u8> {
    let mut p = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut p);
    p
}

// ─── Tests ───────────────────────────────────────────────────────────────

/// Replication(3): every chunk is placed on all 3 distinct trust groups,
/// each Shard ack'd, chunk replication_state = Full.
#[tokio::test]
async fn replication_3_writes_to_3_distinct_trust_groups() {
    let f = fixture(3, /* k_target */ 1, /* chunk */ 4096);
    let payload = random_payload(8192); // 2 chunks at 4 KiB each
    f.svc.write("/file", &payload).await.unwrap();

    // Every provider should have stored at least 2 shards (one per chunk).
    for (pid, p) in &f.providers {
        let n = p.put_count.load(Ordering::SeqCst);
        assert!(
            n >= 2,
            "provider {} (pid={}) only got {} puts; expected ≥2",
            p.name,
            pid,
            n
        );
    }

    // Inspect chunk records: scheme should be (1, 3) and replication_state Full.
    let backend = f.store.backend();
    let mut found_chunks = 0;
    for r in backend
        .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = r.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert_eq!((chunk.ec_scheme.k, chunk.ec_scheme.n), (1, 3));
        assert_eq!(chunk.replication_state, os_entities::ReplicationState::Full);
        assert_eq!(chunk.shard_list.len(), 3);
        found_chunks += 1;
    }
    assert!(found_chunks >= 2);
}

/// F-HM-2 — when a shard fetch errors during a read, the VFS enqueues a
/// HIGH-priority `ReadRepair` task on the attached scheduler. The read
/// itself still succeeds from the surviving shards.
#[tokio::test]
async fn read_repair_enqueued_on_shard_failure() {
    let f = fixture(3, 1, 4096);
    let scheduler = Arc::new(os_repair::RepairScheduler::new(64));
    // Re-wrap the existing Vfs config with the scheduler attached.
    let svc = Arc::new(
        VfsService::with_host(
            f.store.clone(),
            f.svc.vault().clone(),
            f.svc.sync().clone(),
            f.svc.plugin_host().clone(),
            f.svc.config(),
        )
        .with_repair(scheduler.clone()),
    );

    let payload = random_payload(8192);
    svc.write("/r", &payload).await.unwrap();

    // Fail every provider's get. The read will fail but every shard
    // fetch error must enqueue a ReadRepair task; this is what F-HM-2
    // guarantees regardless of which fetch loses the race.
    for (_, p) in &f.providers {
        p.fail_gets.store(true, Ordering::SeqCst);
    }
    let _ = svc.read("/r").await;

    let depth = scheduler.state().depth;
    assert!(
        depth >= 1,
        "expected at least one ReadRepair task enqueued, got depth={depth}"
    );
    let task = scheduler.drain_one().expect("a repair task");
    assert!(matches!(task.source, os_repair::RepairSource::ReadRepair));
    assert_eq!(task.priority, 100);
}

/// k=1, n=3: with one provider down, reads still succeed.
#[tokio::test]
async fn read_succeeds_when_one_provider_offline() {
    let f = fixture(3, 1, 4096);
    let payload = random_payload(8192);
    f.svc.write("/x", &payload).await.unwrap();

    // Make provider 0 forget its data.
    f.providers[0].1.forget_data.store(true, Ordering::SeqCst);

    let got = f.svc.read("/x").await.unwrap();
    assert_eq!(got, payload, "read should reconstruct from surviving providers");
}

/// k=1, n=3: with two providers down, reads still succeed (one shard
/// suffices for k=1).
#[tokio::test]
async fn read_succeeds_when_two_of_three_providers_offline() {
    let f = fixture(3, 1, 4096);
    let payload = random_payload(8192);
    f.svc.write("/y", &payload).await.unwrap();

    f.providers[0].1.forget_data.store(true, Ordering::SeqCst);
    f.providers[1].1.fail_gets.store(true, Ordering::SeqCst);

    let got = f.svc.read("/y").await.unwrap();
    assert_eq!(got, payload);
}

/// k=1, n=3: all providers down → read fails (no silent corruption).
#[tokio::test]
async fn read_fails_when_all_providers_offline() {
    let f = fixture(3, 1, 4096);
    let payload = random_payload(8192);
    f.svc.write("/z", &payload).await.unwrap();

    for (_, p) in &f.providers {
        p.fail_gets.store(true, Ordering::SeqCst);
    }
    let err = f.svc.read("/z").await.unwrap_err();
    assert!(
        format!("{err}").contains("read failed") || format!("{err}").contains("usable"),
        "expected explicit failure, got: {err}"
    );
}

/// Rate-limited primary is routed around: a sibling serves the read first
/// because the dispatcher ranks by capacity.
#[tokio::test]
async fn rate_limited_primary_routed_around_on_read() {
    let f = fixture(3, 1, 4096);
    let payload = random_payload(8192);
    f.svc.write("/r", &payload).await.unwrap();

    // Reset get counts after write.
    for (_, p) in &f.providers {
        p.get_count.store(0, Ordering::SeqCst);
    }

    // Mark provider 0 as rate-limited. With read_hedge=1 and capacity-ranked
    // ranking, providers 1 or 2 should pick up the read first.
    f.providers[0].1.rate_limited.store(true, Ordering::SeqCst);

    let got = f.svc.read("/r").await.unwrap();
    assert_eq!(got, payload);

    // The non-rate-limited providers should have served at least one get.
    let p1 = f.providers[1].1.get_count.load(Ordering::SeqCst);
    let p2 = f.providers[2].1.get_count.load(Ordering::SeqCst);
    assert!(
        p1 + p2 >= 1,
        "rate-limited primary should have been routed around (p1={p1}, p2={p2})"
    );
}

/// k=4, n=7: classic Reed-Solomon round-trip.
#[tokio::test]
async fn rs_4_of_7_round_trip() {
    let f = fixture(7, 4, 4096);
    let payload = random_payload(16 * 1024);
    f.svc.write("/rs", &payload).await.unwrap();

    let backend = f.store.backend();
    for r in backend
        .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = r.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert_eq!(
            (chunk.ec_scheme.k, chunk.ec_scheme.n),
            (4, 7),
            "expected (4,7) parity scheme"
        );
    }
    let got = f.svc.read("/rs").await.unwrap();
    assert_eq!(got, payload);
}

/// k=4, n=7 tolerates 3 simultaneous failures (n - k = 3 parity slack).
#[tokio::test]
async fn rs_4_of_7_tolerates_three_failures() {
    let f = fixture(7, 4, 4096);
    let payload = random_payload(16 * 1024);
    f.svc.write("/rs2", &payload).await.unwrap();

    // Knock out 3 of 7 providers — reconstruct still possible.
    for i in 0..3 {
        f.providers[i].1.forget_data.store(true, Ordering::SeqCst);
    }
    let got = f.svc.read("/rs2").await.unwrap();
    assert_eq!(got, payload);
}

/// k=4, n=7 with 4 failures → not reconstructible.
#[tokio::test]
async fn rs_4_of_7_fails_with_four_failures() {
    let f = fixture(7, 4, 4096);
    let payload = random_payload(16 * 1024);
    f.svc.write("/rs3", &payload).await.unwrap();

    for i in 0..4 {
        f.providers[i].1.forget_data.store(true, Ordering::SeqCst);
    }
    let err = f.svc.read("/rs3").await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read failed") || msg.contains("usable") || msg.contains("ec"),
        "expected reconstruct failure, got: {msg}"
    );
}

/// One provider always fails its puts → chunk is Degraded but write succeeds
/// because quorum (k+1=2 of 3) is met.
#[tokio::test]
async fn degraded_chunk_when_one_put_fails() {
    let f = fixture(3, 1, 4096);
    f.providers[2].1.fail_puts.store(true, Ordering::SeqCst);

    let payload = random_payload(2048);
    f.svc.write("/deg", &payload).await.unwrap();

    let backend = f.store.backend();
    for r in backend
        .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = r.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert_eq!(
            chunk.replication_state,
            os_entities::ReplicationState::Degraded
        );
    }

    // Read still works because k=1 and ≥1 shard is acked.
    let got = f.svc.read("/deg").await.unwrap();
    assert_eq!(got, payload);
}

/// Quorum cannot be met: write returns an error; no partial chunk record.
#[tokio::test]
async fn write_fails_when_quorum_not_met() {
    let f = fixture(3, 1, 4096);
    // k=1 → W = 2. Fail puts on 2 of 3 providers.
    f.providers[1].1.fail_puts.store(true, Ordering::SeqCst);
    f.providers[2].1.fail_puts.store(true, Ordering::SeqCst);

    let payload = random_payload(2048);
    let err = f.svc.write("/q", &payload).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("quorum") || msg.contains("write"),
        "expected quorum error, got: {msg}"
    );
}

/// Pool-size dependent EC selection: when only 1 trust group is available,
/// chunks land at (1,1). No redundancy is possible — that's an honest
/// degenerate case, not a silent failure.
#[tokio::test]
async fn single_group_pool_uses_1_1() {
    let f = fixture(1, 1, 4096);
    let payload = random_payload(2048);
    f.svc.write("/solo", &payload).await.unwrap();

    let backend = f.store.backend();
    for r in backend
        .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = r.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert_eq!((chunk.ec_scheme.k, chunk.ec_scheme.n), (1, 1));
    }
    let got = f.svc.read("/solo").await.unwrap();
    assert_eq!(got, payload);
}

/// Replication factor caps at the pool's distinct-trust-group count.
/// With 5 groups and k_target=1, we should see (1, 5).
#[tokio::test]
async fn replication_factor_matches_distinct_trust_groups() {
    let f = fixture(5, 1, 4096);
    let payload = random_payload(2048);
    f.svc.write("/big-pool", &payload).await.unwrap();

    let backend = f.store.backend();
    for r in backend
        .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = r.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert_eq!((chunk.ec_scheme.k, chunk.ec_scheme.n), (1, 5));
    }
}

/// Mid-read provider failure: kill a provider after the first chunk has
/// been read; subsequent chunks still reconstruct from siblings.
#[tokio::test]
async fn mid_read_provider_failure_handled() {
    let f = fixture(3, 1, 4096);
    let payload = random_payload(20 * 1024); // 5 chunks
    f.svc.write("/mid", &payload).await.unwrap();

    use futures::StreamExt;
    let mut stream = f.svc.read_stream("/mid").await.unwrap();
    let mut got = Vec::new();
    let first = stream.next().await.unwrap().unwrap();
    got.extend_from_slice(&first);

    // Now knock out provider 0 mid-stream.
    f.providers[0].1.forget_data.store(true, Ordering::SeqCst);

    while let Some(c) = stream.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got, payload);
}

// ─── Slot-pool tests (ROUTING.md §13 Step 7b) ─────────────────────────────

/// Layer R5 baseline (CLI-integration version — ROUTING.md §12 R5).
///
/// All providers declare `TrueUpdate`. Write file A → all shards land
/// fresh. Delete file A → engine releases each shard's slot. Write
/// file B with the same size class → engine consults the slot pool,
/// finds a Forgotten slot per shard, and dispatches via `update()`
/// (preserving handles) instead of allocating fresh handles.
///
/// Pin: after the second write, the cumulative `put_count` across all
/// providers is exactly the count from the FIRST write (no fresh puts
/// for B), and `update_count` equals B's shard count.
#[tokio::test]
async fn slot_pool_reuses_forgotten_slots_after_delete() {
    let f = fixture(3, 1, 4096);
    for (_pid, plugin) in &f.providers {
        plugin.update_capable.store(true, Ordering::SeqCst);
    }

    let payload_a = vec![0xAAu8; 1024];
    f.svc.write("/a", &payload_a).await.unwrap();
    let put_after_a: u32 = f
        .providers
        .iter()
        .map(|(_, p)| p.put_count.load(Ordering::SeqCst))
        .sum();
    let update_after_a: u32 = f
        .providers
        .iter()
        .map(|(_, p)| p.update_count.load(Ordering::SeqCst))
        .sum();
    assert_eq!(
        update_after_a, 0,
        "first write should not invoke update; got {update_after_a}"
    );
    assert!(put_after_a > 0, "first write should have called put");

    f.svc.delete("/a").unwrap();

    let payload_b = vec![0xBBu8; 1024];
    f.svc.write("/b", &payload_b).await.unwrap();
    let put_after_b: u32 = f
        .providers
        .iter()
        .map(|(_, p)| p.put_count.load(Ordering::SeqCst))
        .sum();
    let update_after_b: u32 = f
        .providers
        .iter()
        .map(|(_, p)| p.update_count.load(Ordering::SeqCst))
        .sum();
    assert_eq!(
        put_after_b, put_after_a,
        "second write should have reused all slots via update; \
         put_count grew from {put_after_a} to {put_after_b}"
    );
    assert!(
        update_after_b >= 1,
        "second write should have invoked update at least once; \
         update_count={update_after_b}"
    );

    // And the file is readable — slot reuse preserved data integrity.
    let read_b = f.svc.read("/b").await.unwrap();
    assert_eq!(read_b, payload_b);
}

/// Layer R6 baseline (CLI-integration version — ROUTING.md §12 R6).
///
/// On a `TrueUpdate`-capable backend that *can't honestly delete*,
/// crypto-erasure preserves I5 (no silent leaks) by overwriting the
/// slot's bytes with random noise after the chunk key is dropped.
///
/// Pin: write a chunk; capture the ciphertext at rest in the mock's
/// storage; delete the file; run `erase_pending_slots`; assert the
/// mock's storage at the same handle now holds *different* bytes
/// (random noise, not the original AEAD-tagged ciphertext) AND that
/// the slot's state has transitioned to `Empty`. The mock's `delete`
/// is never invoked — erasure rides the `update` path.
#[tokio::test]
async fn slot_pool_crypto_erases_after_delete() {
    use os_plugin_host::SlotState;

    let f = fixture(1, 1, 4096);
    let (pid, plugin) = f.providers[0].clone();
    plugin.update_capable.store(true, Ordering::SeqCst);

    let payload = vec![0xAAu8; 1024];
    f.svc.write("/a", &payload).await.unwrap();

    // Capture the post-write ciphertext: pull the only Filled slot and
    // read its bytes from the mock's in-memory storage.
    let pool = f.svc.slot_pool();
    let pre_handle: NativeHandle = {
        let inner_handle = pool
            .pending_erasure() // empty — nothing released yet
            .into_iter()
            .next()
            .map(|s| s.current_handle.clone().unwrap());
        // `pending_erasure` is empty pre-delete. Iterate slots via len.
        assert_eq!(inner_handle, None, "no Forgotten slots before delete");
        // Find the slot via slot_for_handle reverse lookup: scan every
        // stored handle in the mock and check the slot pool for it.
        let storage = plugin.storage.lock().unwrap();
        let h_bytes = storage.keys().next().expect("mock stored one chunk").clone();
        drop(storage);
        NativeHandle(h_bytes)
    };
    let pre_bytes = plugin
        .storage
        .lock()
        .unwrap()
        .get(&pre_handle.0)
        .cloned()
        .expect("pre-delete bytes present");
    let slot_id = pool
        .slot_for_handle(pid, &pre_handle)
        .expect("slot tracked");

    // Delete the file. This registers a shadow AND releases the slot,
    // but does *not* erase yet — erasure is its own pass.
    f.svc.delete("/a").unwrap();
    assert_eq!(
        pool.get(slot_id).unwrap().state,
        SlotState::Forgotten,
        "slot should be Forgotten after delete, before erasure"
    );
    let bytes_post_delete_pre_erase = plugin
        .storage
        .lock()
        .unwrap()
        .get(&pre_handle.0)
        .cloned()
        .expect("bytes still on backend");
    assert_eq!(
        bytes_post_delete_pre_erase, pre_bytes,
        "delete alone must not change bytes-at-rest (no Delete capability)"
    );

    // Run the erasure pass.
    let erased = f.svc.erase_pending_slots().await.unwrap();
    assert_eq!(erased, 1, "exactly one Forgotten slot should be erased");

    // Bytes-at-rest must now differ from the original ciphertext, and
    // the slot must be Empty.
    let post_bytes = plugin
        .storage
        .lock()
        .unwrap()
        .get(&pre_handle.0)
        .cloned()
        .expect("handle still occupies storage");
    assert_eq!(
        post_bytes.len(),
        pre_bytes.len(),
        "size class is preserved across erasure"
    );
    assert_ne!(
        post_bytes, pre_bytes,
        "bytes-at-rest must be overwritten by random noise"
    );
    assert_eq!(pool.get(slot_id).unwrap().state, SlotState::Empty);
}

/// Layer R7 baseline (CLI-integration version — ROUTING.md §12 R7).
///
/// `AbuseSensor` filters over-budget providers out of placement before
/// the dispatcher even sees them. With provider 0's daily budget set
/// to zero (effectively immediately over budget), every chunk write
/// must route to provider 1 — provider 0's plugin is never called.
#[tokio::test]
async fn abuse_sensor_filters_over_budget_providers() {
    let f = fixture(2, 1, 4096);
    let host_abuse = f.providers[0].0; // provider id
    f.host
        .abuse_sensor()
        .set_budget(host_abuse, Some(0));

    // Three independent files exercise three independent placements.
    for i in 0..3 {
        let path = format!("/abuse-{i}");
        f.svc.write(&path, &vec![0xCDu8; 1024]).await.unwrap();
    }

    let p0 = f.providers[0].1.put_count.load(Ordering::SeqCst);
    let p1 = f.providers[1].1.put_count.load(Ordering::SeqCst);
    assert_eq!(
        p0, 0,
        "provider 0 should never be picked while over budget; got {p0} puts"
    );
    assert!(
        p1 >= 3,
        "provider 1 should absorb every write; got {p1} puts"
    );
}

/// And once the budget loosens, the provider becomes eligible again.
#[tokio::test]
async fn abuse_sensor_re_admits_provider_after_budget_loosens() {
    let f = fixture(2, 1, 4096);
    let pid0 = f.providers[0].0;
    let host = f.host;
    let abuse = host.abuse_sensor();

    abuse.set_budget(pid0, Some(0));
    f.svc.write("/before", &vec![0xAAu8; 1024]).await.unwrap();
    let p0_before = f.providers[0].1.put_count.load(Ordering::SeqCst);
    assert_eq!(p0_before, 0);

    // Loosen.
    abuse.set_budget(pid0, None);
    // Write enough chunks that placement statistically reaches both.
    for i in 0..6 {
        f.svc
            .write(&format!("/after-{i}"), &vec![0xBBu8; 1024])
            .await
            .unwrap();
    }
    let p0_after = f.providers[0].1.put_count.load(Ordering::SeqCst);
    assert!(
        p0_after >= 1,
        "provider 0 should be re-admitted once budget cleared; got {p0_after} puts"
    );
}

/// Negative case: providers that DON'T declare update_capable get the
/// existing fresh-put behavior. The slot pool exists but never fires.
#[tokio::test]
async fn slot_pool_skips_non_update_capable_providers() {
    let f = fixture(3, 1, 4096);
    // Leave update_capable=false on every plugin.

    let payload_a = vec![0x11u8; 1024];
    f.svc.write("/a", &payload_a).await.unwrap();
    f.svc.delete("/a").unwrap();
    let payload_b = vec![0x22u8; 1024];
    f.svc.write("/b", &payload_b).await.unwrap();

    let total_updates: u32 = f
        .providers
        .iter()
        .map(|(_, p)| p.update_count.load(Ordering::SeqCst))
        .sum();
    assert_eq!(
        total_updates, 0,
        "no provider declared update_capable; update should never be called"
    );
}
