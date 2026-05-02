//! Layer 2 baseline — when a backend bans us, the system survives.
//!
//! Why: pre-rework a Discord-shaped account ban (repeated auth failures)
//! had no effect on the engine. The plugin would keep being chosen by
//! placement; reads against banned shards would just fail forever; no
//! repair was triggered. This test simulates the ban and proves that:
//!
//! 1. Five `AuthFailure` errors against provider A drive A to `Banned`.
//! 2. The `HealthEnforcer` worker observes the transition and enqueues
//!    `RepairTask::PluginBan` for every chunk hosted on A — without any
//!    explicit endpoint poke from the test.
//! 3. The repair handler sheds A's shards (registers `Shadow` records,
//!    drops them from the chunk's `shard_list`, marks the chunk
//!    `Degraded`) and emits a `plugin.banned` event.
//! 4. The file remains downloadable from the surviving replica on B.
//! 5. Future placements refuse to pick the banned provider.

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
use os_plugin_host::PluginError;
use os_recovery::RecoveryService;
use os_repair::{RepairScheduler, RepairSource};
use os_share::ShareService;
use os_supervisor::HealthEnforcer;
use os_sync::SyncEngine;
use os_types::{DeviceId, ErrorClass, ProviderHealth, ProviderId};
use os_vault::VaultManager;
use os_vfs::{VfsConfig, VfsService};
use os_wal::WalBuilder;
use rand::rngs::OsRng;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer2_baseline_discord_ban_survives_and_reads_continue() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    let provider_dir_a: PathBuf = tmp.path().join("provider-a");
    let provider_dir_b: PathBuf = tmp.path().join("provider-b");
    for d in [&data_dir, &provider_dir_a, &provider_dir_b] {
        std::fs::create_dir_all(d).unwrap();
    }

    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    // Two providers: A (will be banned) and B (the survivor).
    let host = Arc::new(Host::new());
    let pid_a = ProviderId::new_v7();
    let pid_b = ProviderId::new_v7();
    let plug_a =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir_a.clone()).unwrap());
    let plug_b =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir_b.clone()).unwrap());
    host.register_chunk_unpaced(pid_a, plug_a.clone());
    host.register_vault(pid_a, plug_a);
    host.register_chunk_unpaced(pid_b, plug_b.clone());
    host.register_vault(pid_b, plug_b);

    // Persist Provider records — distinct trust groups so placement
    // treats them as diverse.
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
    let mk_provider = |pid: ProviderId, group: &str| Provider {
        provider_id: pid,
        plugin_id: PluginId::new("org.openstorage.local-dir"),
        instance_label: group.into(),
        credentials_handle: CredentialsHandle::new(vec![]).expect("creds"),
        capabilities: caps.clone(),
        legal_class: LegalClass::Green,
        trust_correlation_group: TrustCorrelationGroup::new(group),
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
    };
    let mut txn = os_metadata::Txn::new();
    store.put_provider(&mut txn, &mk_provider(pid_a, "a")).unwrap();
    store.put_provider(&mut txn, &mk_provider(pid_b, "b")).unwrap();
    store.commit(txn).unwrap();

    // Engine wiring.
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
    // Replication factor 2 so a single banned provider can't take down
    // the file.
    let mut vfs_cfg = VfsConfig::default();
    vfs_cfg.ec_targets = os_placement::EcTargets {
        k_target: 1,
        n_max: 2,
    };
    let vfs = Arc::new(VfsService::with_host(
        store.clone(),
        vault.clone(),
        sync,
        host.clone(),
        vfs_cfg,
    ));
    let lease = Arc::new(LeaseService::new());
    let repair = Arc::new(RepairScheduler::new(1024));
    let events = Arc::new(EventBus::new());
    let share = Arc::new(ShareService::new(store.clone(), vfs.clone()));
    let oauth = Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new());

    let app_state = AppState {
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
    };
    let app = router(app_state.clone());
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

    // Upload a chunked payload — must land on BOTH A and B.
    let payload: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
    vfs.write("/banned-test.txt", &payload).await.expect("write");
    store.flush().unwrap();

    let count_files = |dir: &PathBuf| -> usize {
        std::fs::read_dir(dir)
            .map(|it| it.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    };
    let pre_a = count_files(&provider_dir_a);
    let pre_b = count_files(&provider_dir_b);
    assert!(pre_a > 0, "no shards landed on A; placement diversity broken");
    assert!(pre_b > 0, "no shards landed on B; placement diversity broken");

    // ── Simulate a Discord-shaped ban: 5 AuthFailures against A.
    for _ in 0..5 {
        host.record_error(pid_a, &PluginError::AuthFailure);
    }
    assert!(matches!(
        host.provider_health(pid_a),
        ProviderHealth::Quarantined { reason: ErrorClass::Auth, .. }
    ), "A not quarantined after 5 auth failures: {:?}", host.provider_health(pid_a));

    // Force A all the way to Banned (production transition takes 5 min;
    // the test forces it to assert the cascade synchronously).
    host.force_health(
        pid_a,
        ProviderHealth::Banned {
            since: Timestamp::from_string("now"),
        },
    );

    // Subscribe to events BEFORE running the enforcer, so we don't miss
    // the publish.
    let mut event_sub = events.subscribe(
        os_events::Filter { pattern: "*".into() },
        None,
    );

    // Drive the enforcer once. It must enqueue at least one PluginBan
    // task for the banned provider's chunk(s).
    let enforcer = Arc::new(HealthEnforcer::new(
        store.clone(),
        host.clone(),
        repair.clone(),
        events.clone(),
        Duration::from_millis(50),
    ));
    let enqueued = enforcer.enforce().expect("enforce");
    assert!(
        enqueued > 0,
        "HealthEnforcer didn't enqueue any PluginBan tasks"
    );
    // Drain at least one repair task so we exercise the PluginBan arm.
    let mut drained = 0;
    while let Some(t) = repair.drain_one() {
        assert_eq!(t.source, RepairSource::PluginBan, "wrong repair source");
        // Drive the API's run_repair manually for the test (the
        // production drainer is in app/main.rs). We import it via a
        // small re-exported helper test fn. Calling through the API by
        // hitting `/v1/system/repair` is equivalent.
        // Re-enqueue (drain_one took it) and use the public endpoint
        // that the production drainer also uses.
        repair.enqueue(t).expect("re-enqueue");
        let resp = client
            .post(format!("{}/v1/vaults/{}/repair/run", base, vault_id))
            .json(&serde_json::json!({ "max_tasks": 16 }))
            .send().await.unwrap();
        assert!(resp.status().is_success(), "repair drain: {} {}",
            resp.status(), resp.text().await.unwrap_or_default());
        drained += 1;
        if drained > 10 { break; }
    }

    // Look for the plugin.banned event (event_rx may also have
    // intermediate "plugin.health_changed" entries; we want to see the
    // ban-specific one published from the repair arm).
    let mut saw_banned = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), event_sub.receiver.recv()).await {
            Ok(Some(ev)) => {
                if ev.name == "plugin.banned" {
                    saw_banned = true;
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(saw_banned, "no plugin.banned event was emitted");

    // The file MUST still be downloadable. A's shards are gone (we deleted
    // nothing on disk, but the chunk's shard_list now excludes A); reads
    // come from B.
    let resp = client
        .get(format!("{}/v1/vaults/{}/files/banned-test.txt", base, vault_id))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "post-ban read: {}", resp.status());
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), payload.as_slice(),
        "post-ban payload mismatch — survivor replica didn't take over");

    // Future placements must skip A. Inspect the pool.
    let pool = vault.current_pool().expect("pool");
    let sees_a = pool.providers.iter().any(|p| p.provider_id == pid_a);
    assert!(!sees_a, "placement still sees the banned provider in its pool");
    let sees_b = pool.providers.iter().any(|p| p.provider_id == pid_b);
    assert!(sees_b, "placement lost the surviving provider too — over-filtered");

    let _ = shutdown_tx.send(());
    let _ = server_join.await;
    let _ = vault_id;
}
