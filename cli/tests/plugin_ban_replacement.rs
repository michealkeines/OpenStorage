//! Layer 2 closure baseline (per `STRUCTURAL_REWORK.md` drift item #2):
//! when a provider is Banned, the repair pipeline doesn't just *shed*
//! the affected shards — it re-places them onto another healthy
//! provider so the chunk's replication factor is restored.
//!
//! Pre-fix behavior: the `PluginBan` repair arm registered a `Shadow`
//! for each banned shard, dropped it from the chunk's `shard_list`,
//! and marked the chunk `Degraded`. With (k=1, n=2) and only one
//! survivor left, the durability promise silently dropped from
//! 2 replicas to 1.
//!
//! Post-fix behavior asserted here:
//!   1. Three providers (A, B, C). Chunked upload (n=2) lands on A and
//!      B. C is initially unused.
//!   2. Ban A.
//!   3. Run repair. The handler:
//!        - reconstructs the chunk's ciphertext from B (k=1 so one
//!          surviving shard is enough),
//!        - re-encodes it,
//!        - puts the slot bytes that used to live on A onto C,
//!        - writes a fresh `Shard` record under the deterministic
//!          `shard_id_for(chunk_hash, slot)` (which equals the old
//!          shard_id for that slot, so it overwrites in place),
//!        - shadows A's old native_handle with `PluginBanned`.
//!   4. Final state:
//!        - chunk has bytes on B and C; the `shard_list` carries the
//!          B shard plus a re-placed shard on C,
//!        - the chunk's `replication_state` is `Full` (not Degraded),
//!        - C has at least one new file in its provider dir,
//!        - A still has the original on-disk bytes (we don't reach
//!          into the banned backend to delete; the Shadow lives on),
//!        - the file is byte-identical when downloaded post-repair.

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
use os_repair::{RepairScheduler, RepairSource};
use os_share::ShareService;
use os_supervisor::HealthEnforcer;
use os_sync::SyncEngine;
use os_types::{DeviceId, ProviderHealth, ProviderId};
use os_vault::VaultManager;
use os_vfs::{VfsConfig, VfsService};
use os_wal::WalBuilder;
use rand::rngs::OsRng;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer2_baseline_ban_triggers_replacement_onto_third_provider() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = tmp.path().join("engine-data");
    let provider_dir_a: PathBuf = tmp.path().join("provider-a");
    let provider_dir_b: PathBuf = tmp.path().join("provider-b");
    let provider_dir_c: PathBuf = tmp.path().join("provider-c");
    for d in [&data_dir, &provider_dir_a, &provider_dir_b, &provider_dir_c] {
        std::fs::create_dir_all(d).unwrap();
    }

    let backend = BackendConfig::Sled {
        path: data_dir.join("metadata"),
    }
    .open()
    .unwrap();
    let store = Arc::new(Store::new(backend));

    // Three providers — A and B are picked by initial placement (n=2),
    // C is the spare that re-placement should land the missing shard on.
    let host = Arc::new(Host::new());
    let pid_a = ProviderId::new_v7();
    let pid_b = ProviderId::new_v7();
    let pid_c = ProviderId::new_v7();
    let plug_a =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir_a.clone()).unwrap());
    let plug_b =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir_b.clone()).unwrap());
    let plug_c =
        Arc::new(os_plugin_host::LocalDirPlugin::new(provider_dir_c.clone()).unwrap());
    host.register_chunk_unpaced(pid_a, plug_a.clone());
    host.register_vault(pid_a, plug_a);
    host.register_chunk_unpaced(pid_b, plug_b.clone());
    host.register_vault(pid_b, plug_b);
    host.register_chunk_unpaced(pid_c, plug_c.clone());
    host.register_vault(pid_c, plug_c);

    use os_entities::Provider;
    use os_types::{
        Capability, CapabilitySet, CredentialsHandle, HealthScore, LatencyProfile, LegalClass,
        PluginId, QuotaState, RateLimitState, Timestamp, TrustCorrelationGroup,
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
    store.put_provider(&mut txn, &mk_provider(pid_c, "c")).unwrap();
    store.commit(txn).unwrap();

    // Engine wiring — same shape as the ban-recovery test, with n_max=2
    // so the initial upload picks 2 of the 3 providers and leaves one
    // free for re-placement.
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

    let payload: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
    vfs.write("/replace.txt", &payload).await.expect("write");
    store.flush().unwrap();

    let count_files = |dir: &PathBuf| -> usize {
        std::fs::read_dir(dir)
            .map(|it| it.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    };
    let pre_counts = [
        (pid_a, &provider_dir_a, count_files(&provider_dir_a)),
        (pid_b, &provider_dir_b, count_files(&provider_dir_b)),
        (pid_c, &provider_dir_c, count_files(&provider_dir_c)),
    ];
    let used: Vec<_> = pre_counts.iter().filter(|t| t.2 > 0).collect();
    let unused: Vec<_> = pre_counts.iter().filter(|t| t.2 == 0).collect();
    assert_eq!(
        used.len(),
        2,
        "expected exactly 2 providers used (n_max=2); got {} ({:?})",
        used.len(),
        pre_counts.iter().map(|t| (t.0, t.2)).collect::<Vec<_>>(),
    );
    assert_eq!(unused.len(), 1, "expected exactly 1 unused provider");
    let initial_target_pid = used[0].0;
    let initial_target_dir = used[0].1;
    let surviving_used_dir = used[1].1;
    let initial_unused_dir = unused[0].1;
    let pre_target = used[0].2;
    let pre_surviving = used[1].2;
    let pre_unused = unused[0].2;

    // Force the initial-target provider to Banned. Skip the gradual
    // 5-Auth path here — that's exercised by `plugin_ban_recovery.rs`.
    host.force_health(
        initial_target_pid,
        ProviderHealth::Banned {
            since: Timestamp::from_string("now"),
        },
    );

    // Drive the enforcer to enqueue PluginBan tasks for affected
    // chunks, then drain via the API endpoint (same path production
    // uses).
    let enforcer = Arc::new(HealthEnforcer::new(
        store.clone(),
        host.clone(),
        repair.clone(),
        events.clone(),
        Duration::from_millis(50),
    ));
    let enqueued = enforcer.enforce().expect("enforce");
    assert!(enqueued > 0, "no PluginBan tasks enqueued");

    let mut drained_any = false;
    while let Some(t) = repair.drain_one() {
        assert_eq!(t.source, RepairSource::PluginBan);
        repair.enqueue(t).expect("re-enqueue");
        let resp = client
            .post(format!("{}/v1/vaults/{}/repair/run", base, vault_id))
            .json(&serde_json::json!({ "max_tasks": 16 }))
            .send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "repair drain: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
        drained_any = true;
        // After draining once, re-check; the inner endpoint already
        // drains until the queue empties up to max_tasks.
        if repair.drain_one().is_none() {
            break;
        }
    }
    assert!(drained_any, "no repair task was actually drained");

    // ── Assert structural re-placement happened.
    //
    // (1) The unused provider now hosts at least one new file. (We
    // can't pinpoint exactly which chunk landed on it without
    // reading every Shard record, but a strict file-count increase
    // is sufficient evidence of a re-place.)
    let post_unused = count_files(initial_unused_dir);
    assert!(
        post_unused > pre_unused,
        "re-placement target dir unchanged: pre={} post={} (no re-place happened)",
        pre_unused,
        post_unused,
    );

    // (2) The banned provider's on-disk bytes are NOT touched — we
    // don't reach into a banned backend to delete; the Shadow tracks
    // them for residual accounting. The surviving used provider is
    // also not mutated (re-placement reads from it but writes to the
    // unused one).
    let post_target = count_files(initial_target_dir);
    let post_surviving = count_files(surviving_used_dir);
    assert_eq!(
        post_target, pre_target,
        "banned backend's on-disk file count changed: pre={} post={}",
        pre_target, post_target,
    );
    assert_eq!(
        post_surviving, pre_surviving,
        "surviving used backend's file count changed: pre={} post={}",
        pre_surviving, post_surviving,
    );

    // (3) Every chunk's `replication_state` is `Full` again, and no
    // shard in any chunk's `shard_list` lives on the banned provider.
    use os_metadata::ColumnFamily;
    for kv in store
        .backend()
        .scan_prefix(ColumnFamily::Chunks, b"")
        .unwrap()
    {
        let (_k, v) = kv.unwrap();
        let chunk: os_entities::Chunk = ciborium::from_reader(&v[..]).unwrap();
        assert!(
            matches!(
                chunk.replication_state,
                os_entities::ReplicationState::Full
            ),
            "chunk {} not Full after re-placement: {:?}",
            chunk.chunk_hash,
            chunk.replication_state,
        );
        for sid in &chunk.shard_list {
            let sh = store.get_shard(*sid).unwrap().expect("shard");
            assert_ne!(
                sh.driver_id.value, initial_target_pid,
                "chunk {} still references banned provider in shard_list",
                chunk.chunk_hash
            );
        }
    }

    // (4) A `Shadow` with `PluginBanned` reason exists for the
    // banned native_handles.
    let mut saw_shadow = false;
    for kv in store
        .backend()
        .scan_prefix(ColumnFamily::Shadows, b"")
        .unwrap()
    {
        let (_k, v) = kv.unwrap();
        let sh: os_entities::Shadow = ciborium::from_reader(&v[..]).unwrap();
        if matches!(sh.reason, os_entities::ShadowReason::PluginBanned)
            && sh.driver_id == initial_target_pid
        {
            saw_shadow = true;
            break;
        }
    }
    assert!(
        saw_shadow,
        "no PluginBanned Shadow registered for the banned provider"
    );

    // (5) The file is byte-identical post-repair.
    let resp = client
        .get(format!("{}/v1/vaults/{}/files/replace.txt", base, vault_id))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "post-repair read: {}", resp.status());
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        payload.as_slice(),
        "post-repair payload mismatch — re-placed shard didn't decrypt"
    );

    let _ = shutdown_tx.send(());
    let _ = server_join.await;
}
