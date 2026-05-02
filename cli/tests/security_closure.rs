//! Layer 4 baseline — security claims actually hold.
//!
//! Three sub-pieces land here; one is honestly deferred:
//!
//! 1. Identity rotation requires the lease (§6.A.6). Two devices both
//!    `POST /identity/rotate`; only the lease-holder succeeds.
//! 2. Recovery token rotation invalidates old tokens (§6.A.4). Capture
//!    the on-disk encrypted manifest, rotate the token, attempt unlock
//!    — the active-set check rejects with `recovery_token_revoked`.
//! 3. F-SH-3 revoke re-encrypts inline payloads. Capture the
//!    `inline_payload.ciphertext` bytes before and after revoke; assert
//!    they differ — i.e., a recipient with a cached old `file_key`
//!    can no longer decrypt the post-revoke ciphertext, even with the
//!    same plaintext.
//! 4. **Honestly deferred**: F-SH-3 revoke for *chunked* files. The
//!    structural plumbing for "read source replica → decrypt under old
//!    key → re-encrypt under new key → place" is not yet wired. The
//!    `file_key_version` bumps but the chunk ciphertext on backends
//!    stays decryptable. This is captured as `#[ignore]`'d below so
//!    `cargo test` makes the gap visible without hiding it.

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
use os_types::{DeviceId, ProviderId, Timestamp};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;
use rand::rngs::OsRng;

struct EngineHandle {
    base: String,
    vault_id: String,
    store: Arc<Store>,
    vault: Arc<VaultManager>,
    lease: Arc<LeaseService>,
    recovery: Arc<RecoveryService>,
    device_id: DeviceId,
    shutdown: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

async fn spawn_engine(data_dir: &PathBuf, provider_dir: &PathBuf) -> EngineHandle {
    std::fs::create_dir_all(data_dir).unwrap();
    std::fs::create_dir_all(provider_dir).unwrap();

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

    let app_state = AppState {
        recovery: recovery.clone(),
        vault: vault.clone(),
        vfs,
        identity,
        lease: lease.clone(),
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
    };
    let app = router(app_state);
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

    EngineHandle {
        base,
        vault_id,
        store,
        vault,
        lease,
        recovery,
        device_id,
        shutdown: tx,
        join,
    }
}

async fn drop_engine(h: EngineHandle) {
    let _ = h.shutdown.send(());
    let _ = h.join.await;
}

// ──────────────────────────────────────────────────────────────────────────
// Sub-piece 1 — Identity rotation requires the lease (§6.A.6).
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer4_baseline_identity_rotate_requires_lease() {
    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_engine(
        &tmp.path().join("engine-data"),
        &tmp.path().join("provider"),
    )
    .await;
    let client = reqwest::Client::new();

    // No lease held → rotate must fail with conflict.
    let resp = client
        .post(format!(
            "{}/v1/vaults/{}/identity/rotate",
            h.base, h.vault_id
        ))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !status.is_success(),
        "rotate succeeded without holding the lease: {status} {body}"
    );
    assert!(
        body.to_lowercase().contains("lease"),
        "refusal didn't mention the lease: {body}"
    );

    // Acquire the lease, then rotate succeeds.
    use os_entities::LeaseRecord;
    use os_types::{Ed25519Sig, LeaseId};
    h.lease.install_local(LeaseRecord {
        lease_id: LeaseId::new_v7(),
        holder_device_id: h.device_id,
        acquired_at: Timestamp::from_string("now"),
        expires_at: Timestamp::from_string("+30s"),
        renewal_count: 0,
        holder_signature: Ed25519Sig([0u8; 64]),
    });
    let resp = client
        .post(format!(
            "{}/v1/vaults/{}/identity/rotate",
            h.base, h.vault_id
        ))
        .send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "rotate failed even though we hold the lease: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // Force the lease to a different device → rotate must again fail.
    let other_device = DeviceId::new_v7();
    h.lease.install_local(LeaseRecord {
        lease_id: LeaseId::new_v7(),
        holder_device_id: other_device,
        acquired_at: Timestamp::from_string("now"),
        expires_at: Timestamp::from_string("+30s"),
        renewal_count: 0,
        holder_signature: Ed25519Sig([0u8; 64]),
    });
    let resp = client
        .post(format!(
            "{}/v1/vaults/{}/identity/rotate",
            h.base, h.vault_id
        ))
        .send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !status.is_success(),
        "rotate succeeded while another device held the lease: {status} {body}"
    );

    drop_engine(h).await;
}

// ──────────────────────────────────────────────────────────────────────────
// Sub-piece 2 — Rotated recovery tokens are rejected by `unlock` (§6.A.4).
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer4_baseline_rotated_recovery_token_rejected() {
    use os_entities::RecoveryManifest;
    use os_metadata::ColumnFamily;
    use os_types::{RecoveryTokenId, VaultId};

    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_engine(
        &tmp.path().join("engine-data"),
        &tmp.path().join("provider"),
    )
    .await;

    let vault_id = VaultId::from_uuid(h.vault_id.parse::<uuid::Uuid>().expect("uuid"));

    // Capture the wmk's token id BEFORE rotation — this represents what
    // an externally-generated recovery file would carry on its face.
    let manifest_key = manifest_key_bytes(vault_id);
    let manifest_bytes_pre = h
        .store
        .backend()
        .get(ColumnFamily::VaultMeta, &manifest_key)
        .unwrap()
        .expect("manifest pre-rotate");
    let pre_manifest: RecoveryManifest =
        ciborium::from_reader(&manifest_bytes_pre[..]).expect("decode manifest");
    let old_token_id: RecoveryTokenId = pre_manifest.wrapped_master_keys[0]
        .recovery_token_id;

    // Rotate. Active set is now {new_id}; manifest's wmk now carries
    // new_id.
    h.recovery.rotate_recovery_token(vault_id).expect("rotate");

    // Sanity: unlock with the current (post-rotation) manifest works.
    h.vault.lock().expect("lock");
    h.recovery
        .unlock(vault_id, b"hunter2")
        .expect("post-rotate unlock");

    // ── Now simulate "old recovery file with old token id". Read the
    // current manifest (post-rotation), surgically rewind ONLY the
    // wmk's `recovery_token_id` back to `old_token_id`, write it back.
    // The active_set still contains only `new_id`, so the wmk is no
    // longer valid even though the AEAD wrap still mathematically
    // decrypts.
    h.vault.lock().expect("lock again");
    let cur_bytes = h
        .store
        .backend()
        .get(ColumnFamily::VaultMeta, &manifest_key)
        .unwrap()
        .expect("manifest post-rotate");
    let mut cur_manifest: RecoveryManifest =
        ciborium::from_reader(&cur_bytes[..]).expect("decode manifest");
    cur_manifest.wrapped_master_keys[0].recovery_token_id = old_token_id;
    let mut buf = Vec::new();
    ciborium::into_writer(&cur_manifest, &mut buf).expect("encode");
    let mut txn = os_metadata::Txn::new();
    txn.put(ColumnFamily::VaultMeta, manifest_key.clone(), buf);
    h.store.commit(txn).expect("write tampered manifest");

    let err = h.recovery.unlock(vault_id, b"hunter2");
    let err_str = format!("{:?}", err);
    assert!(
        err_str.contains("TokenRevoked"),
        "unlock with revoked token didn't return TokenRevoked: {err_str}"
    );

    drop_engine(h).await;
}

// ──────────────────────────────────────────────────────────────────────────
// Sub-piece 3 — F-SH-3 revoke re-encrypts inline payload.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer4_baseline_revoke_reencrypts_inline_payload() {
    use os_entities::File as FileRecord;
    use os_metadata::ColumnFamily;
    use os_types::FileId;

    let tmp = tempfile::tempdir().unwrap();
    let h = spawn_engine(
        &tmp.path().join("engine-data"),
        &tmp.path().join("provider"),
    )
    .await;
    let client = reqwest::Client::new();

    // Upload an inline payload.
    let plaintext = b"top secret material that revoke must invalidate";
    let resp = client
        .put(format!(
            "{}/v1/vaults/{}/files/note.txt",
            h.base, h.vault_id
        ))
        .body(plaintext.to_vec())
        .send().await.unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());

    // Find the FileId by scanning the Files CF.
    let mut file_id: Option<FileId> = None;
    let mut pre_revoke_ct: Option<Vec<u8>> = None;
    for kv in h
        .store
        .backend()
        .scan_prefix(ColumnFamily::Files, b"")
        .unwrap()
    {
        let (_k, v) = kv.unwrap();
        if let Ok(f) = ciborium::from_reader::<FileRecord, _>(&v[..]) {
            if f.path.value == "/note.txt" {
                file_id = Some(f.file_id);
                pre_revoke_ct = f.inline_payload.as_ref().map(|p| p.ciphertext.clone());
            }
        }
    }
    let file_id = file_id.expect("file");
    let pre_revoke_ct = pre_revoke_ct.expect("inline payload");

    // Build a VfsService bound to the same store + vault and call the
    // rotate path the share-revoke handler uses internally. This is the
    // structural choke point — bypassing share-blob plumbing keeps the
    // test focused on "ciphertext changed".
    let host = Arc::new(Host::new());
    let sync = Arc::new(SyncEngine::new(Arc::new(
        WalBuilder::new()
            .path(tmp.path().join("rev-wal.bin"))
            .build(h.device_id, generate_keypair(&mut OsRng).0)
            .unwrap(),
    )));
    let vfs = VfsService::with_host(
        h.store.clone(),
        h.vault.clone(),
        sync,
        host,
        os_vfs::VfsConfig::default(),
    );
    let new_version = vfs.rotate_file_key(file_id).expect("rotate");
    assert!(new_version > 0, "version did not bump");

    // Re-read the file; ciphertext must differ.
    let post_revoke_ct = h
        .store
        .get_file(file_id)
        .unwrap()
        .and_then(|f| f.inline_payload.map(|p| p.ciphertext))
        .expect("inline payload after revoke");
    assert_ne!(
        pre_revoke_ct, post_revoke_ct,
        "inline ciphertext is unchanged after revoke — old key still decrypts"
    );

    drop_engine(h).await;
}

// ──────────────────────────────────────────────────────────────────────────
// Sub-piece 4 — Honestly deferred. Chunked file revoke.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Layer 4 follow-up — chunked-file revoke re-encryption is not yet \
            wired. `rotate_file_key` bumps `file_key_version` for chunked \
            files but does NOT read source replicas, decrypt under the old \
            key, re-encrypt under the new key, and re-place. A recipient \
            with cached old `file_key` can still decrypt the on-backend \
            ciphertext. Tracked in STRUCTURAL_REWORK.md L4 drift log."]
async fn layer4_chunked_revoke_actually_invalidates_old_key() {
    panic!("unimplemented — see #[ignore] reason");
}
// ── helpers ───────────────────────────────────────────────────────────────

fn manifest_key_bytes(v: os_types::VaultId) -> Vec<u8> {
    let mut k = b"manifest:".to_vec();
    k.extend_from_slice(v.as_uuid().as_bytes());
    k
}
