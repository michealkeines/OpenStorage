//! Layer 0 baseline — the binary must survive a restart with state intact.
//!
//! Why: pre-rework the production binary used `MemoryBackend`; everything was
//! lost on shutdown. After Layer 0 the binary picks `BackendConfig::Sled`
//! at `<data_dir>/metadata` by default. This test proves it: write file →
//! drop engine → reopen on the same data dir → file is still there with
//! identical bytes.

use std::path::PathBuf;
use std::sync::Arc;

use os_api::{router, AppState};
use os_crypto::generate_keypair;
use os_events::EventBus;
use os_identity::IdentityService;
use os_lease::LeaseService;
use os_metadata::backend::BackendConfig;
use os_metadata::Store;
use os_plugin_host::Host;
use os_recovery::RecoveryService;
use os_repair::RepairScheduler;
use os_share::ShareService;
use os_sync::SyncEngine;
use os_types::{DeviceId, ProviderId};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;

struct EngineHandle {
    base: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

/// Spin an engine that persists state under `data_dir`. The shared
/// `provider_dir` hosts a `LocalDirPlugin` registered as both chunk and
/// vault role (so chunked uploads have somewhere to land across the
/// restart).
async fn spawn_with_data_dir(data_dir: &PathBuf, provider_dir: &PathBuf) -> EngineHandle {
    std::fs::create_dir_all(data_dir).unwrap();
    std::fs::create_dir_all(provider_dir).unwrap();

    let backend_cfg = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    };
    let backend = backend_cfg.open().expect("sled open");
    let store = Arc::new(Store::new(backend));

    let host = Arc::new(Host::new());
    let provider_id = ProviderId::new_v7();
    let plugin = Arc::new(
        os_plugin_host::LocalDirPlugin::new(provider_dir.clone()).expect("local dir plugin"),
    );
    host.register_chunk(provider_id, plugin.clone());
    host.register_vault(provider_id, plugin);

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
    let vfs = Arc::new(VfsService::new(store.clone(), vault.clone(), sync));
    let lease = Arc::new(LeaseService::new());
    let repair = Arc::new(RepairScheduler::new(1024));
    let events = Arc::new(EventBus::new());
    let share = Arc::new(ShareService::new(store, vfs.clone()));
    let oauth = Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new());

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

    EngineHandle {
        base: format!("http://127.0.0.1:{port}"),
        shutdown: tx,
        join,
    }
}

async fn drop_engine(h: EngineHandle) {
    let _ = h.shutdown.send(());
    // Wait for the axum server to actually finish so file handles are
    // released — sled needs the lock back before another process opens it.
    let _ = h.join.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer0_baseline_state_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    let provider_dir: PathBuf = tmp.path().join("provider");

    let payload = b"persisted across a restart".to_vec();
    let path = "/persisted.txt";

    // ── Boot 1 ──
    let h1 = spawn_with_data_dir(&data_dir, &provider_dir).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/vaults", h1.base))
        .json(&serde_json::json!({ "passphrase": "hunter2", "recovery_modes": [] }))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "create: {}", resp.status());
    let v: serde_json::Value = resp.json().await.unwrap();
    let vault_id = v["vault_id"].as_str().unwrap().to_string();

    let resp = client
        .put(format!("{}/v1/vaults/{}/files{}", h1.base, vault_id, path))
        .body(payload.clone())
        .send().await.unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());

    // Confirm the file is readable inside the same process before we cycle.
    let resp = client
        .get(format!("{}/v1/vaults/{}/files{}", h1.base, vault_id, path))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "read pre-restart: {}", resp.status());
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), payload.as_slice(), "pre-restart payload");

    drop_engine(h1).await;

    // ── Boot 2 — same data dir, fresh process state ──
    let h2 = spawn_with_data_dir(&data_dir, &provider_dir).await;

    // Vault is persisted but locked — system status should reflect that.
    let resp = client
        .get(format!("{}/v1/system/status", h2.base))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let status: serde_json::Value = resp.json().await.unwrap();
    let recovered_id = status["vault_id"].as_str().unwrap_or_default();
    assert_eq!(
        recovered_id, vault_id,
        "vault_id changed across restart — sled didn't persist or app rebuilt fresh state"
    );

    // Unlock with the original passphrase.
    let resp = client
        .post(format!("{}/v1/vaults/{}/unlock", h2.base, vault_id))
        .json(&serde_json::json!({ "passphrase": "hunter2" }))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "post-restart unlock: {}", resp.status());

    // Read the file. Bytes must be identical.
    let resp = client
        .get(format!("{}/v1/vaults/{}/files{}", h2.base, vault_id, path))
        .send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "post-restart read: {}",
        resp.status()
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        payload.as_slice(),
        "post-restart payload mismatch — backend didn't actually persist"
    );

    drop_engine(h2).await;
}
