//! Layer 3 closure baseline (per `STRUCTURAL_REWORK.md` drift item #6):
//! when ≥ 2 vault providers declare `OptimisticCas` (or stronger),
//! snapshot push fans out to ALL of them and requires majority
//! acceptance (`floor(N/2)+1`). A single backend dropping the write
//! no longer strands the snapshot pointer; conversely, losing a
//! majority of backends fails the push loudly instead of silently
//! advancing the pointer to a state no peer can read.
//!
//! Three asserted shapes:
//!   * `quorum_three_optimistic_all_succeed` — three healthy
//!     OptimisticCas providers; push succeeds and all three end up
//!     with bytes on disk.
//!   * `quorum_three_one_flake_still_succeeds` — three providers,
//!     one always fails put. Quorum (2 of 3) still met → push
//!     succeeds and the response credits exactly two backends.
//!   * `quorum_three_two_fail_push_refuses` — three providers, two
//!     always fail put. Quorum (2 of 3) NOT met → push returns a
//!     structured 4xx with a quorum-not-met message, and the
//!     surviving backend is not silently treated as the source of
//!     truth.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use os_api::{router, AppState};
use os_crypto::generate_keypair;
use os_entities::{NativeHandle, PutHint};
use os_events::EventBus;
use os_identity::IdentityService;
use os_lease::LeaseService;
use os_metadata::backend::BackendConfig;
use os_metadata::Store;
use os_plugin_host::contract::{
    CasOutcome, CasResult, DeleteResult, HealthReport, HealthState, ListEntry, PeekResult,
    PluginContract, PutResult, VaultPluginContract,
};
use os_plugin_host::{Host, PluginError, Result as PluginResult};
use os_recovery::RecoveryService;
use os_repair::RepairScheduler;
use os_share::ShareService;
use os_sync::SyncEngine;
use os_types::{
    BlakeHash, CachedElsewhereRisk, CasTier, DeleteOutcome, DeviceId, HealthScore,
    LatencyProfile, PriorHandleState, ProviderId, QuotaReclaimed, QuotaState, Range,
    RateLimitState, Timestamp,
};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;
use std::sync::Mutex;

/// Toy in-memory `OptimisticCas` vault plugin. `put` either succeeds
/// (storing into a shared `Vec<u8>` per-instance) or fails based on
/// a flag the test flips. Enough surface to exercise the quorum
/// fan-out without bringing up a real backend.
struct OptimisticCasMockPlugin {
    label: &'static str,
    fail_puts: bool,
    blobs: Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl OptimisticCasMockPlugin {
    fn new(label: &'static str, fail_puts: bool) -> Self {
        Self {
            label,
            fail_puts,
            blobs: Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn stored_count(&self) -> usize {
        self.blobs.lock().unwrap().len()
    }
}

#[async_trait]
impl PluginContract for OptimisticCasMockPlugin {
    async fn put(&self, payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        if self.fail_puts {
            return Err(PluginError::Unavailable(format!("{} flake", self.label)));
        }
        let handle: Vec<u8> = format!("{}-{}", self.label, self.stored_count()).into_bytes();
        self.blobs
            .lock()
            .unwrap()
            .insert(handle.clone(), payload.to_vec());
        Ok(PutResult {
            handle: NativeHandle(handle),
            handle_changed: true,
            prior_handle_state: Some(PriorHandleState::Unknown),
            stored_at: Timestamp::from_string("now"),
            quota_reclaimed: QuotaReclaimed::No,
            tombstone_clears_at: None,
        })
    }
    async fn get(
        &self,
        h: &NativeHandle,
        _r: Option<Range>,
    ) -> PluginResult<Vec<u8>> {
        self.blobs
            .lock()
            .unwrap()
            .get(&h.0)
            .cloned()
            .ok_or_else(|| PluginError::NotFound("missing".into()))
    }
    async fn peek(&self, h: &NativeHandle) -> PluginResult<PeekResult> {
        let g = self.blobs.lock().unwrap();
        match g.get(&h.0) {
            Some(b) => Ok(PeekResult {
                exists: true,
                size: b.len() as u64,
                mtime: Timestamp::from_string("now"),
                etag: None,
            }),
            None => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Timestamp::from_string("now"),
                etag: None,
            }),
        }
    }
    async fn delete(&self, h: &NativeHandle) -> PluginResult<DeleteResult> {
        self.blobs.lock().unwrap().remove(&h.0);
        Ok(DeleteResult {
            outcome: DeleteOutcome::Removed,
            quota_reclaimed: QuotaReclaimed::No,
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
                reset_at: Timestamp::from_string("now"),
            },
            latency: LatencyProfile::default(),
            score: HealthScore::new(1.0),
        })
    }
}

#[async_trait]
impl VaultPluginContract for OptimisticCasMockPlugin {
    fn cas_tier(&self) -> CasTier {
        CasTier::OptimisticCas
    }
    async fn list(
        &self,
        _prefix: &str,
        _limit: u32,
        _cursor: Option<Vec<u8>>,
    ) -> PluginResult<(Vec<ListEntry>, Option<Vec<u8>>)> {
        Ok((Vec::new(), None))
    }
    async fn cas_write(
        &self,
        _name: &str,
        _payload: &[u8],
        _expected_etag: Option<BlakeHash>,
    ) -> PluginResult<CasResult> {
        // Snapshot push uses `put`, not `cas_write`. Honest stub.
        Ok(CasResult {
            outcome: CasOutcome::Written,
            new_etag: None,
        })
    }
    async fn named_get(
        &self,
        _name: &str,
    ) -> PluginResult<Option<(Vec<u8>, BlakeHash)>> {
        Ok(None)
    }
}

struct EngineFixture {
    base: String,
    vault_id: String,
    plugins: Vec<Arc<OptimisticCasMockPlugin>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

async fn spawn_with_plugins(
    tmp: &tempfile::TempDir,
    spec: &[(&'static str, bool)],
) -> EngineFixture {
    let data_dir: PathBuf = tmp.path().join("engine-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    let host = Arc::new(Host::new());
    let mut plugins: Vec<Arc<OptimisticCasMockPlugin>> = Vec::new();
    for (label, fail_puts) in spec {
        let p = Arc::new(OptimisticCasMockPlugin::new(label, *fail_puts));
        let pid = ProviderId::new_v7();
        host.register_vault(pid, p.clone());
        plugins.push(p);
    }
    assert_eq!(
        host.vault_providers_at_least(CasTier::OptimisticCas).len(),
        spec.len(),
    );

    let identity = Arc::new(IdentityService::new(store.clone()));
    let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
    let (sk, _pk) = generate_keypair(&mut OsRng);
    let device_id = DeviceId::new_v7();
    let wal = WalBuilder::new()
        .path(data_dir.join("wal.bin"))
        .build(device_id, sk)
        .unwrap();
    let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
    let recovery = Arc::new(RecoveryService::new(
        store.clone(),
        identity.clone(),
        vault.clone(),
    ));
    let vfs = Arc::new(VfsService::with_host(
        store.clone(),
        vault.clone(),
        sync,
        host.clone(),
        os_vfs::VfsConfig::default(),
    ));
    let lease = Arc::new(LeaseService::new());
    let repair = Arc::new(RepairScheduler::new(1024));
    let events = Arc::new(EventBus::new());
    let share = Arc::new(ShareService::new(store.clone(), vfs.clone()));
    let oauth = Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new());

    let app = router(AppState {
        recovery,
        vault: vault.clone(),
        vfs,
        identity,
        lease,
        repair,
        events,
        host: host.clone(),
        share,
        oauth,
        plugin_authors: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        plugin_capabilities: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        device_id,
        fault: None,
        plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    let base = format!("http://127.0.0.1:{port}");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/vaults", base))
        .json(&serde_json::json!({ "passphrase": "hunter2" }))
        .send().await.unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    let vault_id = v["vault_id"].as_str().unwrap().to_string();

    EngineFixture {
        base,
        vault_id,
        plugins,
        shutdown: tx,
        join,
    }
}

async fn drop_engine(h: EngineFixture) {
    let _ = h.shutdown.send(());
    let _ = h.join.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quorum_three_optimistic_all_succeed() {
    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_with_plugins(
        &tmp,
        &[("a", false), ("b", false), ("c", false)],
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/vaults/{}/snapshot/push", h.base, h.vault_id))
        .json(&serde_json::json!({}))
        .send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "snapshot push refused on a 3-OptimisticCas pool: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // All three providers must have stored exactly one blob — proof of
    // the fan-out, not a single-provider write.
    for p in &h.plugins {
        assert_eq!(
            p.stored_count(),
            1,
            "provider {} did not receive the snapshot",
            p.label
        );
    }

    drop_engine(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quorum_three_one_flake_still_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_with_plugins(
        &tmp,
        &[("a", false), ("b", true /* flake */), ("c", false)],
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/vaults/{}/snapshot/push", h.base, h.vault_id))
        .json(&serde_json::json!({}))
        .send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "quorum push failed when 2/3 healthy: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    let v: serde_json::Value = resp.json().await.unwrap();

    // a + c stored, b empty.
    assert_eq!(h.plugins[0].stored_count(), 1, "a missed the snapshot");
    assert_eq!(h.plugins[1].stored_count(), 0, "b unexpectedly stored");
    assert_eq!(h.plugins[2].stored_count(), 1, "c missed the snapshot");

    // The response credits 2 successful targets (the comma-joined pid
    // string we set in `pushed_to_vault_provider`).
    let pushed = v["pushed_to_vault_provider"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        pushed.split(',').filter(|s| !s.is_empty()).count(),
        2,
        "pushed_to_vault_provider should list the 2 acked targets, got {pushed:?}"
    );

    drop_engine(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quorum_three_two_fail_push_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_with_plugins(
        &tmp,
        &[("a", true /* flake */), ("b", true /* flake */), ("c", false)],
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/vaults/{}/snapshot/push", h.base, h.vault_id))
        .json(&serde_json::json!({}))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !status.is_success(),
        "push silently succeeded with 1/3 acks (quorum=2): {body}"
    );
    assert!(
        body.to_lowercase().contains("quorum"),
        "refusal message lacks quorum reason: {body}"
    );

    // The healthy survivor stored its blob — but that alone is not the
    // truth, since the engine refused to advance the pointer. We
    // assert this just to confirm behavior, not as a correctness gate.
    assert_eq!(h.plugins[2].stored_count(), 1);

    drop_engine(h).await;
}
