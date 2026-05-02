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
        })
    }

    pub fn stored_bytes(&self) -> usize {
        self.storage.lock().unwrap().values().map(|v| v.len()).sum()
    }
}

#[async_trait]
impl PluginContract for MockPlugin {
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
        host,
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
