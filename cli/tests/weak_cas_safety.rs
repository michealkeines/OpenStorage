//! Layer 3 baseline — weak-CAS backends are *refused* for coordination,
//! not silently clobbered.
//!
//! Why: pre-rework `api/src/lib.rs:2237` admitted "the on-plugin pointer
//! would need a name-keyed slot which not every backend exposes
//! consistently" — i.e., on Discord/Catbox/Telegraph the F-SN-1 atomic
//! pointer swap was a *local* CAS only, and two devices pushing
//! concurrently would silently clobber each other.
//!
//! After Layer 3:
//! - Vault plugins declare a `cas_tier()` (StrongCas / OptimisticCas /
//!   EventualOnly).
//! - Snapshot push refuses to run when no registered vault provider
//!   meets `OptimisticCas`. The error is explicit, not silent.
//! - Chunk-role is unaffected; chunks are content-addressed and
//!   tolerate weak backends just fine.

use std::path::PathBuf;
use std::sync::Arc;

use os_api::{router, AppState};
use os_crypto::generate_keypair;
use os_entities::{NativeHandle, PutHint};
use os_events::EventBus;
use os_identity::IdentityService;
use os_lease::LeaseService;
use os_metadata::backend::BackendConfig;
use os_metadata::Store;
use os_plugin_host::contract::{
    CasOutcome, CasResult, DeleteResult, HealthReport, HealthState, ListEntry, ObjectBytes,
    PeekResult, PluginContract, PutResult, VaultPluginContract,
};
use os_plugin_host::{Host, PluginError, Result as PluginResult};
use os_recovery::RecoveryService;
use os_repair::RepairScheduler;
use os_share::ShareService;
use os_sync::SyncEngine;
use os_types::{
    AeadTag, BlakeHash, CachedElsewhereRisk, CasTier, DeleteOutcome, DeviceId, HealthScore,
    LatencyProfile, PriorHandleState, ProviderId, QuotaReclaimed, QuotaState, Range,
    RateLimitState, Timestamp,
};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;

/// A vault plugin that declares `EventualOnly`. Every coordination
/// primitive (cas_write) returns `NotSupported`; named_get pretends not
/// found. The point of the test is that the engine *refuses* to use
/// this for snapshot push, not that the operations succeed.
struct EventualOnlyVaultPlugin;

#[async_trait::async_trait]
impl PluginContract for EventualOnlyVaultPlugin {
    async fn put(&self, _payload: &[u8], _hint: &PutHint) -> PluginResult<PutResult> {
        Ok(PutResult {
            handle: NativeHandle(b"x".to_vec()),
            handle_changed: false,
            prior_handle_state: Some(PriorHandleState::Unknown),
            stored_at: Timestamp::from_string("now"),
            quota_reclaimed: QuotaReclaimed::No,
            tombstone_clears_at: None,
        })
    }
    async fn get(&self, _h: &NativeHandle, _r: Option<Range>) -> PluginResult<Vec<u8>> {
        Err(PluginError::NotFound("eventual-only".into()))
    }
    async fn peek(&self, _h: &NativeHandle) -> PluginResult<PeekResult> {
        Ok(PeekResult {
            exists: true,
            size: 1,
            mtime: Timestamp::from_string("now"),
            etag: None,
        })
    }
    async fn delete(&self, _h: &NativeHandle) -> PluginResult<DeleteResult> {
        Ok(DeleteResult {
            outcome: DeleteOutcome::NotSupported,
            quota_reclaimed: QuotaReclaimed::No,
            cached_elsewhere_risk: CachedElsewhereRisk::High,
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

#[async_trait::async_trait]
impl VaultPluginContract for EventualOnlyVaultPlugin {
    fn cas_tier(&self) -> CasTier {
        CasTier::EventualOnly
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
        // EventualOnly = no CAS. The honest answer is NotSupported.
        Ok(CasResult {
            outcome: CasOutcome::NotSupported,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer3_baseline_eventual_only_refused_for_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    // Register only an EventualOnly vault plugin. No StrongCas/OptimisticCas
    // is available — the engine must refuse snapshot push.
    let host = Arc::new(Host::new());
    let pid = ProviderId::new_v7();
    host.register_vault(pid, Arc::new(EventualOnlyVaultPlugin));

    // Verify the host introspection reports the tier correctly.
    assert_eq!(host.vault_cas_tier(pid), Some(CasTier::EventualOnly));
    assert!(host
        .vault_providers_at_least(CasTier::OptimisticCas)
        .is_empty());

    // Engine wiring (just enough to spin the API).
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
        vfs: vfs.clone(),
        identity,
        lease,
        repair: repair.clone(),
        events: events.clone(),
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_join = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
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

    // The snapshot push MUST fail with an explicit Layer-3 message — not
    // silently succeed against a backend that can't honor CAS.
    let resp = client
        .post(format!("{}/v1/vaults/{}/snapshot/push", base, vault_id))
        .json(&serde_json::json!({}))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !status.is_success(),
        "snapshot push silently succeeded against EventualOnly backend; \
         body={body}"
    );
    assert!(
        body.to_lowercase().contains("eventual")
            || body.contains("Layer 3")
            || body.to_lowercase().contains("cas"),
        "refusal message lacks the structural reason: {body}"
    );

    let _ = shutdown_tx.send(());
    let _ = server_join.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer3_strongcas_provider_succeeds() {
    // Same scaffolding but with a `LocalDirPlugin` (declared StrongCas)
    // — confirms the refusal isn't blanket-blocking; only weak-CAS
    // providers are rejected.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    let provider_dir: PathBuf = tmp.path().join("provider");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&provider_dir).unwrap();

    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    let host = Arc::new(Host::new());
    let pid = ProviderId::new_v7();
    let local =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir.clone()).unwrap());
    host.register_chunk_unpaced(pid, local.clone());
    host.register_vault(pid, local);

    assert_eq!(host.vault_cas_tier(pid), Some(CasTier::StrongCas));

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
        vfs: vfs.clone(),
        identity,
        lease,
        repair: repair.clone(),
        events: events.clone(),
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_join = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
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

    let resp = client
        .post(format!("{}/v1/vaults/{}/snapshot/push", base, vault_id))
        .json(&serde_json::json!({}))
        .send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "snapshot push refused on StrongCas backend (over-filter): {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    let _ = shutdown_tx.send(());
    let _ = server_join.await;
}

// ObjectBytes is imported but not used — silence the warning by
// referring to the type so dead-code analysis stays quiet.
#[allow(dead_code)]
fn _refer_object_bytes() -> Option<ObjectBytes> {
    None
}

// ──────────────────────────────────────────────────────────────────────────
// Layer 3 closure baseline (per `STRUCTURAL_REWORK.md` drift item #5):
// the lease and WAL push paths must apply the same CAS-tier filter as
// snapshot push. Pre-fix they accepted any registered vault provider —
// meaning a Discord-only deployment would silently install the
// per-vault lease blob on a backend that can't honor cas_write, and
// concurrent peers could clobber each other's leases.
// ──────────────────────────────────────────────────────────────────────────

async fn spawn_eventual_only_engine(
    tmp: &tempfile::TempDir,
) -> (
    String,
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let data_dir: PathBuf = tmp.path().join("engine-data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    let host = Arc::new(Host::new());
    let pid = ProviderId::new_v7();
    host.register_vault(pid, Arc::new(EventualOnlyVaultPlugin));
    assert_eq!(host.vault_cas_tier(pid), Some(CasTier::EventualOnly));

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

    (base, vault_id, tx, join)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer3_baseline_eventual_only_refused_for_wal_push() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, vault_id, shutdown, join) = spawn_eventual_only_engine(&tmp).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/vaults/{}/wal/push", base, vault_id))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !status.is_success(),
        "wal push silently succeeded against EventualOnly backend; body={body}"
    );
    let lc = body.to_lowercase();
    assert!(
        lc.contains("eventual") || lc.contains("cas") || lc.contains("layer 3"),
        "wal push refusal lacks CAS-tier reason: {body}"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer3_baseline_eventual_only_refused_for_lease_steal() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, vault_id, shutdown, join) = spawn_eventual_only_engine(&tmp).await;

    let client = reqwest::Client::new();
    // /lease/steal is the load-bearing CAS-coupled lease op (F-MD-4).
    // It must refuse on EventualOnly: a successful "steal" without
    // honest CAS would trample a peer's existing lease.
    let resp = client
        .post(format!("{}/v1/vaults/{}/lease/steal", base, vault_id))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    // The handler may return a structured-bad message OR fall through
    // a no-vault-plugin code path that surfaces the same CAS-tier
    // reason; either way it must NOT report success.
    assert!(
        !status.is_success(),
        "lease/steal silently succeeded against EventualOnly backend; body={body}"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}
