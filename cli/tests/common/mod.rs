//! Shared test harness: spins up an in-process engine on a random port and
//! returns its base URL plus the `OPENSTORAGE_*` env this test process should
//! pass to the `os` CLI binary.

use std::path::PathBuf;
use std::sync::Arc;

use os_api::{router, AppState};
use os_crypto::generate_keypair;
use os_events::EventBus;
use os_identity::IdentityService;
use os_lease::LeaseService;
use os_metadata::backend::MemoryBackend;
use os_metadata::Store;
use os_plugin_host::Host;
use os_recovery::RecoveryService;
use os_repair::RepairScheduler;
use os_share::ShareService;
use os_sync::SyncEngine;
use os_types::DeviceId;
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;

pub struct Engine {
    pub base: String,
    pub state_path: PathBuf,
    /// Hold the runtime alive for the duration of the test.
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

/// F-MD-1..5 — pair of engines that share a single LocalDirPlugin
/// directory as their vault provider. Each engine has its own metadata
/// store, WAL, and device id, but writes go through the same on-disk
/// `name:lease/<vault>` and `name:wal/<device>/<seq>` slots so
/// cross-device coordination is observable.
pub struct EnginePair {
    pub a: Engine,
    pub b: Engine,
    pub provider_id: os_types::ProviderId,
    pub shared_dir: PathBuf,
}

#[allow(dead_code)]
pub async fn spawn_engine_pair() -> EnginePair {
    let mut shared = std::env::temp_dir();
    shared.push(format!("os-cli-md-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&shared).unwrap();
    let provider_id = os_types::ProviderId::new_v7();
    let a = spawn_engine_with_shared_provider(provider_id, shared.clone()).await;
    let b = spawn_engine_with_shared_provider(provider_id, shared.clone()).await;
    EnginePair {
        a,
        b,
        provider_id,
        shared_dir: shared,
    }
}

#[allow(dead_code)]
pub async fn spawn_engine_with_shared_provider(
    provider_id: os_types::ProviderId,
    shared_dir: PathBuf,
) -> Engine {
    spawn_engine_inner(Some((provider_id, shared_dir))).await
}

pub async fn spawn_engine() -> Engine {
    spawn_engine_inner(None).await
}

async fn spawn_engine_inner(
    shared_provider: Option<(os_types::ProviderId, PathBuf)>,
) -> Engine {
    let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
    let host = Arc::new(Host::new());
    if let Some((pid, dir)) = &shared_provider {
        let plugin = Arc::new(
            os_plugin_host::LocalDirPlugin::new(dir.clone()).expect("local dir plugin"),
        );
        // Register as both chunk and vault role: F-MD-* needs vault-role
        // (cas_write/named_get) and the rest of the harness still expects
        // chunk-role for writes through the file API. Use *_unpaced so
        // tests don't sit behind the rate-limit middleware.
        host.register_chunk_unpaced(*pid, plugin.clone());
        host.register_vault(*pid, plugin);

        // Layer 5 — persist a Provider record so placement can pick
        // this provider for chunked writes. Without this the chunk
        // path returns "no providers with required capabilities".
        use os_entities::Provider;
        use os_types::{
            Capability, CapabilitySet, CredentialsHandle, HealthScore, LatencyProfile,
            LegalClass, PluginId, QuotaState, RateLimitState, Timestamp,
            TrustCorrelationGroup,
        };
        let caps = CapabilitySet::default()
            .with(Capability::Put)
            .with(Capability::Get)
            .with(Capability::Peek)
            .with(Capability::Delete);
        let mut txn = os_metadata::Txn::new();
        let _ = store.put_provider(
            &mut txn,
            &Provider {
                provider_id: *pid,
                plugin_id: PluginId::new("org.openstorage.local-dir"),
                instance_label: "test".into(),
                credentials_handle: CredentialsHandle::new(vec![]).expect("creds"),
                capabilities: caps,
                legal_class: LegalClass::Green,
                trust_correlation_group: TrustCorrelationGroup::new("local"),
                quota: QuotaState {
                    total: None,
                    used: None,
                    untrusted: false,
                },
                rate_limit: RateLimitState {
                    remaining: u32::MAX,
                    reset_at: Timestamp::from_string("now"),
                },
                health: HealthScore::new(1.0),
                latency: LatencyProfile::default(),
                untrusted_quota: false,
            },
        );
        let _ = store.commit(txn);
    }
    let identity = Arc::new(IdentityService::new(store.clone()));
    let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
    let mut tdir = std::env::temp_dir();
    tdir.push(format!("os-cli-it-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tdir).unwrap();
    let (sk, _pk) = generate_keypair(&mut OsRng);
    let device_id = DeviceId::new_v7();
    let wal = WalBuilder::new()
        .path(tdir.join("wal.bin"))
        .build(device_id, sk)
        .unwrap();
    let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
    let recovery = Arc::new(RecoveryService::new(
        store.clone(),
        identity.clone(),
        vault.clone(),
    ));
    // Layer 5 — bind VFS to the engine's Host so chunked writes route
    // through the registered plugin. Previously `VfsService::new`
    // constructed a fresh empty Host, so chunked tests in
    // shared-provider mode silently failed.
    let vfs = Arc::new(os_vfs::VfsService::with_host(
        store.clone(),
        vault.clone(),
        sync,
        host.clone(),
        os_vfs::VfsConfig::default(),
    ));
    let _ = VfsService::new; // suppress unused-import lint; left for future
    let lease = Arc::new(LeaseService::new());
    let repair = Arc::new(RepairScheduler::new(1024));
    let events = Arc::new(EventBus::new());
    let share = Arc::new(ShareService::new(store, vfs.clone()));
    let oauth = Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new());
    let plugin_authors = Arc::new(std::sync::RwLock::new(
        std::collections::HashMap::new(),
    ));
    let plugin_capabilities = Arc::new(std::sync::RwLock::new(
        std::collections::HashMap::new(),
    ));
    let app = router(AppState {
        recovery,
        vault,
        vfs,
        identity,
        lease,
        repair,
        events,
        host,
        share,
        oauth,
        plugin_authors,
        plugin_capabilities,
        device_id,
        fault: None,
        plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    let mut state_dir = tdir.clone();
    state_dir.push("cli-state");
    std::fs::create_dir_all(&state_dir).unwrap();
    Engine {
        base: format!("http://127.0.0.1:{port}"),
        state_path: state_dir,
        _shutdown_tx: tx,
    }
}
