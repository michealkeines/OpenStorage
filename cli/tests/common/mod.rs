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

pub async fn spawn_engine() -> Engine {
    let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
    let host = Arc::new(Host::new());
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
    let vfs = Arc::new(VfsService::new(store, vault.clone(), sync));
    let lease = Arc::new(LeaseService::new());
    let repair = Arc::new(RepairScheduler::new(1024));
    let events = Arc::new(EventBus::new());
    let app = router(AppState {
        recovery,
        vault,
        vfs,
        identity,
        lease,
        repair,
        events,
        host,
        device_id,
        fault: None,
        plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
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
