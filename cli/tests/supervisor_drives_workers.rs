//! Layer 1 baseline — the supervisor autonomously drives workers.
//!
//! Why: pre-rework the engine had endpoints to scrub/gc/anti-entropy but
//! no timer firing them. F-HM-1 promised "timer; runs". This test
//! proves the autonomous claim is real: corrupt a shard, sit idle, and
//! the scrub worker independently detects the corruption and enqueues a
//! repair task — *without* the test calling any endpoint.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
use os_supervisor::{Scrubber, Supervisor};
use os_sync::SyncEngine;
use os_types::{DeviceId, ProviderId};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer1_baseline_supervisor_detects_missing_shard_autonomously() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    let provider_dir: PathBuf = tmp.path().join("provider");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&provider_dir).unwrap();

    // Sled backend (Layer 0) so the wiring matches production exactly.
    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    // LocalDirPlugin so we can tamper with the on-disk shards directly.
    let host = Arc::new(Host::new());
    let provider_id = ProviderId::new_v7();
    let local =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir.clone()).unwrap());
    host.register_chunk_unpaced(provider_id, local.clone());
    host.register_vault(provider_id, local);

    // Persist a Provider record so placement sees the registered plugin.
    use os_entities::Provider;
    use os_types::{
        Capability, CapabilitySet, CredentialsHandle, HealthScore, LatencyProfile,
        LegalClass, PluginId, QuotaState, RateLimitState, Timestamp, TrustCorrelationGroup,
    };
    let caps = CapabilitySet::default()
        .with(Capability::Put)
        .with(Capability::Get)
        .with(Capability::Peek)
        .with(Capability::Delete);
    let mut txn = os_metadata::Txn::new();
    store
        .put_provider(
            &mut txn,
            &Provider {
                provider_id,
                plugin_id: PluginId::new("org.openstorage.local-dir"),
                instance_label: "test".into(),
                credentials_handle: CredentialsHandle::new(vec![])
                    .expect("empty creds"),
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
        )
        .unwrap();
    store.commit(txn).unwrap();

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
    // Create vault.
    let resp = client
        .post(format!("{}/v1/vaults", base))
        .json(&serde_json::json!({ "passphrase": "hunter2", "recovery_modes": [] }))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "create: {}", resp.status());
    let v: serde_json::Value = resp.json().await.unwrap();
    let vault_id = v["vault_id"].as_str().unwrap().to_string();

    // Upload a payload that exceeds the inline threshold (16 KiB) so we
    // hit the chunked path and produce real Shard records on disk.
    let payload: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
    vfs.write("/scrub-me.txt", &payload)
        .await
        .expect("vfs write");
    let _ = vault_id;
    store.flush().unwrap();

    // ── Tamper: delete every file under the provider dir. The
    // shards' bytes are gone; the next scrub tick must notice.
    let mut deleted = 0;
    for entry in std::fs::read_dir(&provider_dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            std::fs::remove_file(&p).unwrap();
            deleted += 1;
        }
    }
    assert!(deleted > 0, "no shards on disk to tamper with");

    // Spawn the supervisor with a fast scrub interval. Crucially, the
    // test never calls any repair endpoint after this point — if a
    // repair task lands in the queue, the supervisor put it there.
    let cancel = CancellationToken::new();
    let scrub = Arc::new(Scrubber::new(
        store.clone(),
        host.clone(),
        repair.clone(),
        events.clone(),
        Duration::from_millis(100),
    ));
    let sup = Supervisor::new(cancel.clone()).with_worker(scrub);
    let mut set = sup.run();

    // Poll up to 5 s for the queue to grow.
    let mut observed_depth = 0usize;
    for _ in 0..50 {
        let st = repair.state();
        if st.depth > 0 {
            observed_depth = st.depth;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cancel.cancel();
    while set.join_next().await.is_some() {}
    let _ = shutdown_tx.send(());
    let _ = server_join.await;

    assert!(
        observed_depth > 0,
        "scrubber never enqueued a repair task — supervisor isn't autonomous"
    );
}
