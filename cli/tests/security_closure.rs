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
    vfs: Arc<VfsService>,
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

    // Persist a Provider row so `current_pool()` discovers this backend
    // when chunked-upload placement runs. Without this row a >16 KiB
    // upload returns 400 because placement has nowhere to write.
    {
        use os_entities::Provider;
        use os_types::{
            Capability, CapabilitySet, CredentialsHandle, HealthScore, LatencyProfile,
            LegalClass, PluginId, QuotaState, RateLimitState, TrustCorrelationGroup,
        };
        let caps = CapabilitySet::default()
            .with(Capability::Put)
            .with(Capability::Get)
            .with(Capability::Peek)
            .with(Capability::Delete);
        let p = Provider {
            provider_id: pid,
            plugin_id: PluginId::new("org.openstorage.local-dir"),
            instance_label: "test-local".into(),
            credentials_handle: CredentialsHandle::new(vec![]).expect("creds"),
            capabilities: caps,
            legal_class: LegalClass::Green,
            trust_correlation_group: TrustCorrelationGroup::new("test"),
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
        store.put_provider(&mut txn, &p).unwrap();
        store.commit(txn).unwrap();
    }

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
    let vfs_for_handle = vfs.clone();
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
        vfs: vfs_for_handle,
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

    // Drive the rotate path directly on the engine's VFS — same choke
    // point the share-revoke handler uses. Skipping share-blob plumbing
    // keeps the test focused on "ciphertext changed".
    let new_version = h.vfs.rotate_file_key(file_id).await.expect("rotate");
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
// Sub-piece 4 — F-SH-3 chunked file revoke.
//
// Closes the Layer 4 drift item. Asserts that after `rotate_file_key` on a
// chunked file:
//   1. `file_key_version` actually bumps,
//   2. every chunk's ciphertext on the backend is different bytes,
//   3. the old `file_key` (derived at the previous version) can NO LONGER
//      AEAD-decrypt the new on-backend ciphertext — i.e. a recipient who
//      cached the pre-revoke file_key is genuinely locked out, not just
//      flagged as locked out in metadata,
//   4. the owner can still read the file (sanity: re-encryption preserves
//      plaintext through the new version's key),
//   5. a `Shadow` with `ShadowReason::KeyRevoked` was registered for each
//      Acked shard, so the old ciphertext on the backend is tracked for
//      eventual GC instead of leaking quota silently.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn layer4_chunked_revoke_actually_invalidates_old_key() {
    use os_chunk::reconstruct_and_decrypt;
    use os_crypto::derive_chunk_key;
    use os_entities::{Chunk, File as FileRecord, Shadow};
    use os_metadata::ColumnFamily;
    use os_types::FileId;
    use os_vfs::derive_file_key;

    let tmp = tempfile::tempdir().unwrap();
    let provider_dir = tmp.path().join("provider");
    let h = spawn_engine(&tmp.path().join("engine-data"), &provider_dir).await;

    // Upload a file large enough to take the chunked path. Default
    // inline threshold is 16 KiB; pick 96 KiB and fill with a varied
    // pattern so a "did the bytes change?" check can't be fooled by
    // accidental constant ciphertext.
    let plaintext: Vec<u8> = (0..96 * 1024)
        .map(|i| ((i * 31 + 7) ^ (i >> 5)) as u8)
        .collect();
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}/v1/vaults/{}/files/big.bin", h.base, h.vault_id))
        .body(plaintext.clone())
        .send().await.unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());

    // Locate the FileId + the chunk graph via direct CF scans (no
    // chunked-file API exposes this — the test owns the structural
    // invariant that revoke touches every shard, not just the file row).
    let mut file_id: Option<FileId> = None;
    let mut chunk_list: Vec<os_types::ChunkHash> = Vec::new();
    for kv in h.store.backend().scan_prefix(ColumnFamily::Files, b"").unwrap() {
        let (_k, v) = kv.unwrap();
        if let Ok(f) = ciborium::from_reader::<FileRecord, _>(&v[..]) {
            if f.path.value == "/big.bin" {
                file_id = Some(f.file_id);
                chunk_list = f.chunk_list.clone().expect("chunked file");
                break;
            }
        }
    }
    let file_id = file_id.expect("file");
    assert!(
        chunk_list.len() >= 1,
        "expected chunked file; got {} chunks",
        chunk_list.len()
    );

    // Snapshot the OLD on-backend bytes per chunk, plus the AEAD nonce/tag
    // and shard ciphertext lengths captured at write time. These are what
    // a revoked recipient could have cached.
    struct ChunkSnap {
        plaintext_length: u64,
        ec_scheme: os_types::ECScheme,
        nonce: os_types::AeadNonce,
        tag: os_types::AeadTag,
        slot_bytes: Vec<Option<Vec<u8>>>, // indexed by shard_index
    }
    let read_handle_bytes = |handle: &os_entities::NativeHandle| -> Vec<u8> {
        std::fs::read(provider_dir.join(hex::encode(&handle.0))).unwrap()
    };
    let mut old_snaps: Vec<ChunkSnap> = Vec::with_capacity(chunk_list.len());
    let mut old_handles: Vec<os_entities::NativeHandle> = Vec::new();
    for ch in &chunk_list {
        let chunk: Chunk = h.store.get_chunk(*ch).unwrap().expect("chunk record");
        let n = chunk.ec_scheme.n as usize;
        let mut slot_bytes: Vec<Option<Vec<u8>>> = vec![None; n];
        let mut nonce: Option<os_types::AeadNonce> = None;
        let mut tag: Option<os_types::AeadTag> = None;
        for sid in &chunk.shard_list {
            let s = h.store.get_shard(*sid).unwrap().expect("shard record");
            if matches!(s.ack_state, os_entities::AckState::Acked) {
                let bytes = read_handle_bytes(&s.native_handle.value);
                slot_bytes[s.shard_index as usize] = Some(bytes);
                nonce.get_or_insert(s.encryption_nonce.clone());
                tag.get_or_insert(s.encryption_tag);
                old_handles.push(s.native_handle.value.clone());
            }
        }
        old_snaps.push(ChunkSnap {
            plaintext_length: chunk.plaintext_length,
            ec_scheme: chunk.ec_scheme,
            nonce: nonce.expect("at least one acked shard"),
            tag: tag.expect("at least one acked shard"),
            slot_bytes,
        });
    }

    // Sanity: the cached OLD ciphertext + OLD file_key actually decrypts to
    // the original plaintext. (If this assertion fails the test is
    // mis-wired before we even revoke.)
    {
        let mk = h.vault.master_key().expect("master key");
        let old_file_key = derive_file_key(&mk, file_id, 0).unwrap();
        let mut all = Vec::with_capacity(plaintext.len());
        for (idx, snap) in old_snaps.iter().enumerate() {
            let cck = derive_chunk_key(&old_file_key, idx as u64).unwrap();
            let pt = reconstruct_and_decrypt(
                snap.slot_bytes.clone(),
                chunk_list[idx],
                &cck,
                &snap.nonce,
                &snap.tag,
                os_types::AeadSuite::ChaCha20Poly1305,
                snap.ec_scheme,
                snap.plaintext_length,
            )
            .expect("decrypt with OLD key (sanity)");
            all.extend_from_slice(&pt);
        }
        assert_eq!(all, plaintext, "test setup: old key did not decrypt own bytes");
    }

    // Drive `rotate_file_key` against the engine's VFS — the same host
    // that wrote the original chunks is reused, so the freshly-placed
    // re-encrypted shards land in the same provider directory and the
    // pool/placement plumbing sees a valid Provider row already.
    let new_version = h.vfs.rotate_file_key(file_id).await.expect("rotate");
    assert_eq!(new_version, 1, "version did not bump to 1");

    // Re-read the file row + chunk graph; capture NEW on-disk bytes and
    // assert they differ from the old.
    let new_file: FileRecord = ciborium::from_reader(
        &h.store
            .backend()
            .get(ColumnFamily::Files, file_id.as_uuid().as_bytes())
            .unwrap()
            .expect("file post-revoke")[..],
    )
    .unwrap();
    assert_eq!(new_file.file_key_version, 1);
    let new_chunk_list = new_file.chunk_list.expect("still chunked");
    assert_eq!(new_chunk_list, chunk_list, "chunk_hash list must be stable");

    let mk = h.vault.master_key().expect("mk");
    let old_file_key = derive_file_key(&mk, file_id, 0).unwrap();
    let new_file_key = derive_file_key(&mk, file_id, 1).unwrap();

    for (idx, ch) in new_chunk_list.iter().enumerate() {
        let chunk: Chunk = h.store.get_chunk(*ch).unwrap().expect("chunk post-revoke");
        let n = chunk.ec_scheme.n as usize;
        let mut new_slot_bytes: Vec<Option<Vec<u8>>> = vec![None; n];
        let mut new_nonce: Option<os_types::AeadNonce> = None;
        let mut new_tag: Option<os_types::AeadTag> = None;
        for sid in &chunk.shard_list {
            let s = h.store.get_shard(*sid).unwrap().expect("shard post-revoke");
            if matches!(s.ack_state, os_entities::AckState::Acked) {
                let bytes = read_handle_bytes(&s.native_handle.value);
                new_slot_bytes[s.shard_index as usize] = Some(bytes);
                new_nonce.get_or_insert(s.encryption_nonce.clone());
                new_tag.get_or_insert(s.encryption_tag);
            }
        }
        let new_nonce = new_nonce.expect("post-revoke acked shard");
        let new_tag = new_tag.expect("post-revoke acked shard");

        // (i) new bytes differ from old, slot-by-slot, on at least one slot.
        let mut any_changed = false;
        for slot in 0..n {
            let (Some(old), Some(new)) = (
                old_snaps[idx].slot_bytes[slot].as_ref(),
                new_slot_bytes[slot].as_ref(),
            ) else {
                continue;
            };
            if old != new {
                any_changed = true;
                break;
            }
        }
        assert!(
            any_changed,
            "chunk {idx} ciphertext on backend is byte-identical after revoke"
        );

        // (ii) old file_key cannot decrypt the NEW on-disk ciphertext. We
        // try the new nonce+tag (which is what's actually on the wire) under
        // the OLD chunk_key. AEAD must fail.
        let old_chunk_key = derive_chunk_key(&old_file_key, idx as u64).unwrap();
        let res = reconstruct_and_decrypt(
            new_slot_bytes.clone(),
            *ch,
            &old_chunk_key,
            &new_nonce,
            &new_tag,
            os_types::AeadSuite::ChaCha20Poly1305,
            chunk.ec_scheme,
            chunk.plaintext_length,
        );
        assert!(
            res.is_err(),
            "old file_key still decrypts new ciphertext for chunk {idx}",
        );

        // (iii) new file_key DOES decrypt and produces the right bytes.
        let new_chunk_key = derive_chunk_key(&new_file_key, idx as u64).unwrap();
        let pt = reconstruct_and_decrypt(
            new_slot_bytes,
            *ch,
            &new_chunk_key,
            &new_nonce,
            &new_tag,
            os_types::AeadSuite::ChaCha20Poly1305,
            chunk.ec_scheme,
            chunk.plaintext_length,
        )
        .expect("new key must decrypt new ciphertext");
        // Plaintext length per chunk = whole file's plaintext length up to
        // chunk_bytes. Verify against the corresponding slice.
        let chunk_bytes = os_vfs::VfsConfig::default().chunk_bytes;
        let start = idx * chunk_bytes;
        let end = (start + pt.len()).min(plaintext.len());
        assert_eq!(
            pt,
            plaintext[start..end],
            "new key decrypts to wrong plaintext for chunk {idx}"
        );
    }

    // (iv) Owner can still download via the engine (round-trip through HTTP).
    let resp = client
        .get(format!("{}/v1/vaults/{}/files/big.bin", h.base, h.vault_id))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "owner download: {}", resp.status());
    let dl = resp.bytes().await.unwrap().to_vec();
    assert_eq!(dl, plaintext, "owner cannot read post-revoke file");

    // (v) Shadow with KeyRevoked exists for each old shard handle.
    let mut shadow_handles: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for kv in h.store.backend().scan_prefix(ColumnFamily::Shadows, b"").unwrap() {
        let (_k, v) = kv.unwrap();
        let s: Shadow = ciborium::from_reader(&v[..]).unwrap();
        if matches!(s.reason, os_entities::ShadowReason::KeyRevoked) {
            shadow_handles.insert(s.native_handle.0.clone());
        }
    }
    for h_bytes in &old_handles {
        assert!(
            shadow_handles.contains(&h_bytes.0),
            "old handle {} was not shadowed with KeyRevoked",
            hex::encode(&h_bytes.0)
        );
    }

    drop_engine(h).await;
}
// ── helpers ───────────────────────────────────────────────────────────────

fn manifest_key_bytes(v: os_types::VaultId) -> Vec<u8> {
    let mut k = b"manifest:".to_vec();
    k.extend_from_slice(v.as_uuid().as_bytes());
    k
}
