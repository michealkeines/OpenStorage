//! os-vfs — VFS service. Orchestrates file writes and reads on top of
//! `metadata`, `crypto`, `chunk`, `ec`, `placement`, `plugin_host`, and `sync`.
//!
//! Two paths:
//! - **inline**: payloads ≤ `inline_threshold_bytes` get encrypted as a
//!   single AEAD blob inside the `File` record.
//! - **chunked**: payloads larger than that are split into fixed-size chunks,
//!   each AEAD-encrypted with a per-chunk derived key, EC-encoded into shards,
//!   and shipped to plugins. Chunk and Shard records track the placement.
//!
//! Streaming: `write_stream` and `read_stream` work in fixed-size chunks so
//! large files don't load fully into memory.

#![forbid(unsafe_code)]

use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures::Stream;
use os_chunk::{encrypt_and_encode, hash as chunk_hash_bytes, reconstruct_and_decrypt};
use os_crypto::{
    decrypt as aead_decrypt, derive_chunk_key, derive_subkey, encrypt as aead_encrypt,
    random_nonce_12,
};
use os_entities::{
    Chunk, File, InlineBlob, LwwRegister, NativeHandle, Op, OrSet, Permissions, PutHint,
    ReplicationState, Shard, AckState,
};
use os_metadata::{Store, Txn};
use os_placement::{pick_shards_for_chunk, select_ec_scheme, DiversityPolicy, EcTargets};
use os_plugin_host::Host;
use os_sync::SyncEngine;
use os_types::{
    AeadSuite, ChunkHash, ECScheme, FileId, HealthScore, Hlc, KeyPurpose, ProviderId, ShardId,
    Tier, Timestamp,
};
use os_vault::VaultManager;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Error)]
pub enum VfsError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("vault locked")]
    VaultLocked,
    #[error("metadata: {0}")]
    Metadata(String),
    #[error("crypto: {0:?}")]
    Crypto(os_crypto::CryptoError),
    #[error("chunk: {0:?}")]
    Chunk(os_chunk::ChunkError),
    #[error("plugin: {0}")]
    Plugin(String),
    #[error("placement: {0}")]
    Placement(String),
    #[error("vault: {0}")]
    Vault(String),
    #[error("io: {0}")]
    Io(String),
    #[error("sync: {0}")]
    Sync(String),
}

impl From<os_metadata::MetadataError> for VfsError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}
impl From<os_crypto::CryptoError> for VfsError {
    fn from(e: os_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<os_chunk::ChunkError> for VfsError {
    fn from(e: os_chunk::ChunkError) -> Self {
        Self::Chunk(e)
    }
}
impl From<os_plugin_host::PluginError> for VfsError {
    fn from(e: os_plugin_host::PluginError) -> Self {
        Self::Plugin(e.to_string())
    }
}
impl From<os_placement::PlacementError> for VfsError {
    fn from(e: os_placement::PlacementError) -> Self {
        Self::Placement(e.to_string())
    }
}
impl From<os_vault::VaultError> for VfsError {
    fn from(e: os_vault::VaultError) -> Self {
        Self::Vault(e.to_string())
    }
}
impl From<os_sync::SyncError> for VfsError {
    fn from(e: os_sync::SyncError) -> Self {
        Self::Sync(e.to_string())
    }
}
impl From<std::io::Error> for VfsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VfsConfig {
    pub inline_threshold_bytes: usize,
    pub chunk_bytes: usize,
    pub aead_suite: AeadSuite,
    /// **Caller targets**, not a static scheme. The actual `(k, n)` is
    /// chosen per chunk by `os_placement::select_ec_scheme` against the
    /// live pool snapshot, so deployments transparently scale from
    /// single-copy (one trust group) up to the spec default of (4, 7) as
    /// the user adds backends. Mixed schemes coexist; each chunk's record
    /// stores the scheme used to write it (RESILIENCE §3.2).
    pub ec_targets: EcTargets,
    /// Hedge factor for reads: fire `K + read_hedge` parallel gets, take
    /// first K (DESIGN §6.4 / STATES_AND_FLOWS F-FL-1).
    pub read_hedge: u8,
    /// Max concurrent in-flight chunk persists during a streaming write.
    /// Reads still flow sequentially from the source; this overlaps the
    /// per-chunk encrypt+EC+upload work so a single slow backend does not
    /// stall the whole upload. Bounded so memory stays linear in this knob.
    pub chunk_upload_concurrency: usize,
    /// Same idea on the read side: how many *chunks* are fetched in
    /// parallel during a streaming read. (Within one chunk, K+H shard
    /// fetches always race per the hedged-read design.)
    pub chunk_fetch_concurrency: usize,
}

impl Default for VfsConfig {
    fn default() -> Self {
        Self {
            inline_threshold_bytes: 16 * 1024,
            chunk_bytes: 4 * 1024 * 1024,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            ec_targets: EcTargets::default(),
            read_hedge: 1,
            chunk_upload_concurrency: 8,
            chunk_fetch_concurrency: 8,
        }
    }
}

pub struct VfsService {
    store: Arc<Store>,
    vault: Arc<VaultManager>,
    sync: Arc<SyncEngine>,
    plugin_host: Arc<Host>,
    cfg: VfsConfig,
}

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub file_id: FileId,
    pub path: String,
    pub size_bytes: u64,
    pub modified_at: Timestamp,
    pub content_type: String,
    pub exists: bool,
}

impl VfsService {
    pub fn new(
        store: Arc<Store>,
        vault: Arc<VaultManager>,
        sync: Arc<SyncEngine>,
    ) -> Self {
        Self::with_host(store, vault, sync, Arc::new(Host::new()), VfsConfig::default())
    }
    pub fn with_host(
        store: Arc<Store>,
        vault: Arc<VaultManager>,
        sync: Arc<SyncEngine>,
        plugin_host: Arc<Host>,
        cfg: VfsConfig,
    ) -> Self {
        Self {
            store,
            vault,
            sync,
            plugin_host,
            cfg,
        }
    }

    pub fn config(&self) -> VfsConfig {
        self.cfg
    }

    // ─── small/buffered helpers ────────────────────────────────────────────
    pub async fn write(&self, path: &str, bytes: &[u8]) -> Result<FileMeta, VfsError> {
        let cursor = std::io::Cursor::new(bytes.to_vec());
        self.write_stream(path, cursor, Some(bytes.len() as u64)).await
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let mut out = Vec::new();
        let mut stream = self.read_stream(path).await?;
        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    // ─── streaming write ───────────────────────────────────────────────────
    /// Stream-write a file. `size_hint` is used to pick the inline path early;
    /// pass `None` if unknown.
    pub async fn write_stream<R: AsyncRead + Unpin + Send>(
        &self,
        path: &str,
        mut reader: R,
        size_hint: Option<u64>,
    ) -> Result<FileMeta, VfsError> {
        let mk = self.vault.master_key().ok_or(VfsError::VaultLocked)?;
        let device = self.sync.wal().device_id();
        let now = Timestamp::from_string(now_iso());

        // Existing file?
        let existing = self.find_by_path(path)?;
        let file_id = existing.as_ref().map(|f| f.file_id).unwrap_or_else(FileId::new_v7);

        // If size is known and small, take inline path directly.
        if let Some(s) = size_hint {
            if (s as usize) <= self.cfg.inline_threshold_bytes {
                let mut buf = Vec::with_capacity(s as usize);
                reader.read_to_end(&mut buf).await?;
                return self.commit_inline(path, file_id, &buf, &mk, device, &now, existing);
            }
        }

        // Try inline first by reading up to threshold + 1 byte.
        let mut head = Vec::with_capacity(self.cfg.inline_threshold_bytes + 1);
        let limit = self.cfg.inline_threshold_bytes as u64 + 1;
        let n = (&mut reader)
            .take(limit)
            .read_to_end(&mut head)
            .await
            .map_err(|e| VfsError::Io(e.to_string()))?;
        if n <= self.cfg.inline_threshold_bytes {
            // Whole file fit. EOF reached.
            return self.commit_inline(path, file_id, &head[..n], &mk, device, &now, existing);
        }

        // Chunked path. We've already read the first chunk's worth of bytes
        // into `head`; treat that as the start of the stream.
        // Per F-FL-5 the file_key is bound to the stable `file_id` and
        // `file_key_version` (bumped by F-SH-3 revoke), not to the path.
        let file_key_version = existing.as_ref().map(|f| f.file_key_version).unwrap_or(0);
        let file_key = derive_file_key(&mk, file_id, file_key_version)?;
        let vault_salt: Option<Vec<u8>> = self
            .vault
            .vault_id()
            .and_then(|_| self.vault.master_key())
            .map(|mk| {
                derive_subkey(&mk, KeyPurpose::VAULT_SALT, None)
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default()
            });

        // Pipeline: read sequentially (one mut-borrowed reader) and push
        // each chunk's encrypt+EC+upload as a future onto a bounded
        // FuturesOrdered. Order is preserved so chunk_list matches input
        // order even with multiple in-flight persists.
        use futures::stream::{FuturesOrdered, StreamExt};

        let concurrency = self.cfg.chunk_upload_concurrency.max(1);
        let mut inflight: FuturesOrdered<
            std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(ChunkHash, u64), VfsError>> + Send + '_>,
            >,
        > = FuturesOrdered::new();
        let mut chunk_list: Vec<ChunkHash> = Vec::new();
        let mut total_size: u64 = 0;

        let mut leftover: Vec<u8> = head;
        let mut chunk_index: u64 = 0;
        let mut eof = false;
        loop {
            // Drain to make room if we hit the concurrency cap.
            while inflight.len() >= concurrency {
                if let Some(r) = inflight.next().await {
                    let (h, sz) = r?;
                    chunk_list.push(h);
                    total_size += sz;
                } else {
                    break;
                }
            }
            if eof {
                break;
            }

            // Read one chunk's worth of bytes.
            let mut chunk_buf = std::mem::take(&mut leftover);
            let initial_len = chunk_buf.len();
            chunk_buf.resize(self.cfg.chunk_bytes, 0);
            let mut filled = initial_len;
            while filled < self.cfg.chunk_bytes {
                let read = reader
                    .read(&mut chunk_buf[filled..])
                    .await
                    .map_err(|e| VfsError::Io(e.to_string()))?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            chunk_buf.truncate(filled);
            if chunk_buf.is_empty() {
                eof = true;
                continue;
            }
            if chunk_buf.len() < self.cfg.chunk_bytes {
                eof = true;
            }

            let mut salted = Vec::with_capacity(8 + vault_salt.as_deref().map_or(0, |s| s.len()));
            salted.extend_from_slice(&chunk_index.to_be_bytes());
            if let Some(s) = vault_salt.as_deref() {
                salted.extend_from_slice(s);
            }
            let chunk_h = chunk_hash_bytes(&chunk_buf, Some(&salted));
            let chunk_key = derive_chunk_key(&file_key, chunk_index)?;
            let idx = chunk_index;
            chunk_index += 1;

            // Spawn-equivalent: build a future borrowing &self that does
            // encrypt + placement + upload + metadata persist. Order is
            // preserved by FuturesOrdered.
            let fut = async move {
                let sz = chunk_buf.len() as u64;
                self.persist_chunk(chunk_h, idx, &chunk_buf, &chunk_key).await?;
                Ok::<(ChunkHash, u64), VfsError>((chunk_h, sz))
            };
            inflight.push_back(Box::pin(fut));
        }
        // Drain any remaining in-flight persists.
        while let Some(r) = inflight.next().await {
            let (h, sz) = r?;
            chunk_list.push(h);
            total_size += sz;
        }

        let hlc = next_hlc(&self.sync);
        let file = match existing {
            Some(mut f) => {
                f.size_bytes = LwwRegister::new(total_size, hlc, device);
                f.modified_at = LwwRegister::new(now.clone(), hlc, device);
                f.exists = LwwRegister::new(true, hlc, device);
                f.inline_payload = None;
                f.chunk_list = Some(chunk_list);
                f
            }
            None => File {
                file_id,
                path: LwwRegister::new(path.into(), hlc, device),
                size_bytes: LwwRegister::new(total_size, hlc, device),
                created_at: LwwRegister::new(now.clone(), hlc, device),
                modified_at: LwwRegister::new(now.clone(), hlc, device),
                permissions: LwwRegister::new(Permissions::default(), hlc, device),
                content_type: LwwRegister::new(String::new(), hlc, device),
                tier_pinned: LwwRegister::new(None, hlc, device),
                inline_payload: None,
                chunk_list: Some(chunk_list),
                wrapped_keys: OrSet::new(),
                acl: OrSet::new(),
                exists: LwwRegister::new(true, hlc, device),
                file_key_version: 0,
            },
        };
        let mut txn = Txn::new();
        self.store.put_file(&mut txn, &file)?;
        self.store.commit(txn)?;
        // skip per-record WAL emission for now (chunked file metadata is too
        // large for a single WAL entry without indirection).
        let _ = Op::LwwRegister {
            target: os_entities::Key::new(
                os_entities::KeyKind::File,
                file.file_id.as_uuid().as_bytes().to_vec(),
                "_record",
            ),
            value: Vec::new(),
        };

        Ok(FileMeta {
            file_id: file.file_id,
            path: file.path.value,
            size_bytes: file.size_bytes.value,
            modified_at: file.modified_at.value,
            content_type: file.content_type.value,
            exists: file.exists.value,
        })
    }

    fn commit_inline(
        &self,
        path: &str,
        file_id: FileId,
        bytes: &[u8],
        mk: &os_crypto::SymKey,
        device: os_types::DeviceId,
        now: &Timestamp,
        existing: Option<File>,
    ) -> Result<FileMeta, VfsError> {
        let file_key_version = existing.as_ref().map(|f| f.file_key_version).unwrap_or(0);
        let file_key = derive_file_key(mk, file_id, file_key_version)?;
        let aad = inline_aad(file_id, file_key_version);
        let nonce = random_nonce_12();
        let (ct, tag) = aead_encrypt(self.cfg.aead_suite, &file_key, &nonce, bytes, &aad)?;
        let hlc = next_hlc(&self.sync);
        let file = match existing {
            Some(mut f) => {
                f.size_bytes = LwwRegister::new(bytes.len() as u64, hlc, device);
                f.modified_at = LwwRegister::new(now.clone(), hlc, device);
                f.exists = LwwRegister::new(true, hlc, device);
                f.inline_payload = Some(InlineBlob {
                    ciphertext: ct,
                    nonce,
                    tag,
                });
                f.chunk_list = None;
                f
            }
            None => File {
                file_id,
                path: LwwRegister::new(path.into(), hlc, device),
                size_bytes: LwwRegister::new(bytes.len() as u64, hlc, device),
                created_at: LwwRegister::new(now.clone(), hlc, device),
                modified_at: LwwRegister::new(now.clone(), hlc, device),
                permissions: LwwRegister::new(Permissions::default(), hlc, device),
                content_type: LwwRegister::new(String::new(), hlc, device),
                tier_pinned: LwwRegister::new(None, hlc, device),
                inline_payload: Some(InlineBlob {
                    ciphertext: ct,
                    nonce,
                    tag,
                }),
                chunk_list: None,
                wrapped_keys: OrSet::new(),
                acl: OrSet::new(),
                exists: LwwRegister::new(true, hlc, device),
                file_key_version: 0,
            },
        };
        let mut txn = Txn::new();
        self.store.put_file(&mut txn, &file)?;
        self.store.commit(txn)?;
        Ok(FileMeta {
            file_id: file.file_id,
            path: file.path.value,
            size_bytes: file.size_bytes.value,
            modified_at: file.modified_at.value,
            content_type: file.content_type.value,
            exists: file.exists.value,
        })
    }

    // ─── chunk persistence ─────────────────────────────────────────────────
    /// Quorum-acked write per DESIGN row 140 / STATES_AND_FLOWS F-FL-2:
    ///
    /// 1. Pool snapshot → dynamic `(k, n)` via `select_ec_scheme`.
    /// 2. Encrypt + EC-encode the chunk plaintext into N shards.
    /// 3. Place shards across distinct trust groups (with same-group
    ///    siblings as fallback for liveness against rate-limits).
    /// 4. Fire **N parallel puts**.
    /// 5. Return success at **W = k + 1 acks** (write durability).
    /// 6. Continue draining the remaining (N − W) puts; chunk transitions
    ///    `Degraded` → `Full` once all N land.
    /// 7. Failed shards: `Shard.ack_state = Pending` is recorded (placeholder)
    ///    so the repair scheduler can find them; chunk is `Degraded`.
    async fn persist_chunk(
        &self,
        chunk_h: ChunkHash,
        chunk_index: u64,
        plaintext: &[u8],
        chunk_key: &os_crypto::SymKey,
    ) -> Result<(), VfsError> {
        let _ = chunk_index;
        let pool = self.vault.current_pool()?;

        // Dynamic EC selection (RESILIENCE §3.2). Each chunk records its
        // own scheme; deployments scale from (1,1) on a single-group pool
        // through replication on small pools to (k, n) parity coding once
        // ≥k+1 distinct trust groups are configured.
        let scheme = select_ec_scheme(&pool, self.cfg.ec_targets);
        let enc = encrypt_and_encode(plaintext, chunk_h, chunk_key, self.cfg.aead_suite, scheme, None)?;

        let policy = DiversityPolicy {
            require_distinct_trust_groups: scheme.n > 1,
            prefer_legal_diversity: false,
        };
        let picks = pick_shards_for_chunk(chunk_h, scheme, &pool, policy, Tier::Hot)?;
        if picks.len() != enc.shards.len() {
            return Err(VfsError::Placement(format!(
                "placement returned {} picks, expected {}",
                picks.len(),
                enc.shards.len()
            )));
        }

        // Build (shard_index → candidate_list) where the primary is the
        // placement choice and same-trust-group siblings are dispatcher
        // fallbacks (rate-limit liveness, not redundancy).
        let primary_groups = group_lookup(&pool, &picks);
        let mut already_used: std::collections::BTreeSet<os_types::TrustCorrelationGroup> =
            std::collections::BTreeSet::new();
        struct ShardJob {
            shard_index: u8,
            shard_id: os_types::ShardId,
            candidates: Vec<ProviderId>,
            ciphertext: Vec<u8>,
        }
        let mut jobs: Vec<ShardJob> = Vec::with_capacity(enc.shards.len());
        for (es, (shard_index, primary_id)) in enc.shards.iter().zip(picks.iter()) {
            let group = primary_groups
                .get(primary_id)
                .cloned()
                .unwrap_or_else(|| os_types::TrustCorrelationGroup::new("unknown"));
            let mut candidates: Vec<ProviderId> = vec![*primary_id];
            for entry in &pool.providers {
                if entry.provider_id == *primary_id {
                    continue;
                }
                if entry.trust_group == group
                    && (!policy.require_distinct_trust_groups
                        || !already_used.contains(&entry.trust_group))
                {
                    candidates.push(entry.provider_id);
                }
            }
            already_used.insert(group);
            jobs.push(ShardJob {
                shard_index: *shard_index,
                shard_id: es.shard_id,
                candidates,
                ciphertext: es.ciphertext.clone(),
            });
        }

        let n = scheme.n as usize;
        let k = scheme.k as usize;
        // W = k + 1 (DESIGN row 758). Capped at n for tiny pools.
        let w = (k + 1).min(n);

        // Fan out N parallel puts via FuturesUnordered.
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut inflight: FuturesUnordered<
            std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = (
                                u8,
                                os_types::ShardId,
                                Result<os_plugin_host::PutDispatched, os_plugin_host::PluginError>,
                                u64,
                            ),
                        > + Send,
                >,
            >,
        > = FuturesUnordered::new();
        for job in jobs {
            let host = self.plugin_host.clone();
            let ct_len = job.ciphertext.len() as u64;
            let shard_index = job.shard_index;
            let shard_id = job.shard_id;
            let candidates = job.candidates;
            let ciphertext = job.ciphertext;
            let fut = async move {
                let r = os_plugin_host::PoolDispatcher::put_with_fallback(
                    &host,
                    &candidates,
                    &ciphertext,
                    &PutHint::default(),
                    os_plugin_host::DispatcherConfig::default(),
                )
                .await;
                (shard_index, shard_id, r, ct_len)
            };
            inflight.push(Box::pin(fut));
        }

        // Collect results: drain to W acks, then keep draining for full
        // replication (we still want to record every ack; the Degraded
        // marker only appears if some permanently fail).
        struct AckedShard {
            shard_index: u8,
            shard_id: os_types::ShardId,
            provider_id: ProviderId,
            handle: os_entities::NativeHandle,
            ct_len: u64,
        }
        struct FailedShard {
            shard_index: u8,
            shard_id: os_types::ShardId,
        }
        let mut acked: Vec<AckedShard> = Vec::with_capacity(n);
        let mut failed: Vec<FailedShard> = Vec::new();
        let mut quorum_ok = false;

        while let Some((shard_index, shard_id, result, ct_len)) = inflight.next().await {
            match result {
                Ok(dispatched) => {
                    acked.push(AckedShard {
                        shard_index,
                        shard_id,
                        provider_id: dispatched.provider_id,
                        handle: dispatched.handle,
                        ct_len,
                    });
                    if !quorum_ok && acked.len() >= w {
                        quorum_ok = true;
                        // Per design we *could* return success here and
                        // background-drain the rest. We choose to drain
                        // synchronously so the persisted Chunk record
                        // accurately reflects every shard's terminal
                        // state in one transaction. The chunk-upload
                        // pipeline (FuturesOrdered in write_stream)
                        // already overlaps work *across* chunks, so
                        // serializing within one chunk is fine.
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        chunk = %chunk_h, %shard_id, ?e,
                        "shard put failed; chunk will be degraded"
                    );
                    failed.push(FailedShard { shard_index, shard_id });
                }
            }
        }

        if acked.len() < w {
            return Err(VfsError::Plugin(format!(
                "quorum not met: {} of {} required acks (n={}, k={})",
                acked.len(),
                w,
                n,
                k
            )));
        }

        let replication_state = if failed.is_empty() {
            ReplicationState::Full
        } else {
            ReplicationState::Degraded
        };

        // Build Shard records: Acked for successful, Pending placeholder
        // for failed (so repair scheduler / scrub can find them). The
        // shard_list on Chunk includes ALL N entries — partial coverage is
        // discoverable, not silent.
        let mut shard_records: Vec<Shard> = Vec::with_capacity(n);
        let now = Timestamp::from_string(now_iso());
        let device = self.sync.wal().device_id();
        for a in &acked {
            shard_records.push(Shard {
                shard_id: a.shard_id,
                chunk_hash: chunk_h,
                shard_index: a.shard_index,
                encryption_nonce: enc.nonce.clone(),
                encryption_tag: enc.tag,
                ciphertext_length: a.ct_len,
                driver_id: os_entities::LwwSet::new(
                    a.provider_id,
                    None,
                    next_hlc(&self.sync),
                    device,
                ),
                native_handle: os_entities::LwwSet::new(
                    a.handle.clone(),
                    None,
                    next_hlc(&self.sync),
                    device,
                ),
                stored_at: now.clone(),
                last_verified_at: now.clone(),
                health_score: HealthScore::new(1.0),
                ack_state: AckState::Acked,
            });
        }
        for f in &failed {
            shard_records.push(Shard {
                shard_id: f.shard_id,
                chunk_hash: chunk_h,
                shard_index: f.shard_index,
                encryption_nonce: enc.nonce.clone(),
                encryption_tag: enc.tag,
                ciphertext_length: 0,
                driver_id: os_entities::LwwSet::new(
                    ProviderId::new_v7(), // sentinel; repair will rewrite
                    None,
                    next_hlc(&self.sync),
                    device,
                ),
                native_handle: os_entities::LwwSet::new(
                    os_entities::NativeHandle(Vec::new()),
                    None,
                    next_hlc(&self.sync),
                    device,
                ),
                stored_at: now.clone(),
                last_verified_at: now.clone(),
                health_score: HealthScore::new(0.0),
                ack_state: AckState::Failed,
            });
        }

        // Order shard_list by shard_index for stable iteration on read.
        shard_records.sort_by_key(|s| s.shard_index);

        let chunk = Chunk {
            chunk_hash: chunk_h,
            plaintext_length: enc.plaintext_length,
            ec_scheme: scheme,
            shard_list: shard_records.iter().map(|s| s.shard_id).collect(),
            refcount: os_entities::Counter::default(),
            replication_state,
            last_scrubbed_at: now.clone(),
            access_count_window: os_entities::Counter::default(),
            tier: Tier::Hot,
        };
        let mut txn = Txn::new();
        self.store.put_chunk(&mut txn, &chunk)?;
        for s in &shard_records {
            self.store.put_shard(&mut txn, s)?;
        }
        self.store.commit(txn)?;
        Ok(())
    }

    // ─── streaming read ────────────────────────────────────────────────────
    pub async fn read_stream(
        &self,
        path: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes, VfsError>> + Send>>, VfsError> {
        let mk = self.vault.master_key().ok_or(VfsError::VaultLocked)?;
        let file = self
            .find_by_path(path)?
            .ok_or_else(|| VfsError::NotFound(path.into()))?;
        if !file.exists.value {
            return Err(VfsError::NotFound(path.into()));
        }
        let path_owned = path.to_string();

        // Inline → single-shot stream.
        if let Some(payload) = file.inline_payload.clone() {
            let file_key = derive_file_key(&mk, file.file_id, file.file_key_version)?;
            let aad = inline_aad(file.file_id, file.file_key_version);
            let pt = aead_decrypt(
                self.cfg.aead_suite,
                &file_key,
                &payload.nonce,
                &payload.ciphertext,
                &payload.tag,
                &aad,
            )?;
            let stream = futures::stream::iter(vec![Ok(Bytes::from(pt))]);
            return Ok(Box::pin(stream));
        }

        let chunk_list = file.chunk_list.clone().ok_or_else(|| {
            VfsError::Metadata(format!("file {} has neither inline nor chunks", path_owned))
        })?;
        let cfg = self.cfg;
        let store = self.store.clone();
        let plugin_host = self.plugin_host.clone();
        let file_key = derive_file_key(&mk, file.file_id, file.file_key_version)?;
        let fetch_concurrency = cfg.chunk_fetch_concurrency.max(1);
        let read_hedge = cfg.read_hedge as usize;
        let stream = async_stream::try_stream! {
            use futures::stream::FuturesOrdered;
            use futures::StreamExt;

            let mut inflight: FuturesOrdered<
                std::pin::Pin<Box<dyn std::future::Future<Output = Result<Bytes, VfsError>> + Send>>,
            > = FuturesOrdered::new();
            let mut next_idx: usize = 0;
            let total = chunk_list.len();

            loop {
                while inflight.len() < fetch_concurrency && next_idx < total {
                    let idx = next_idx;
                    next_idx += 1;
                    let ch = chunk_list[idx];
                    let store = store.clone();
                    let plugin_host = plugin_host.clone();
                    let file_key = file_key.clone();
                    let aead_suite = cfg.aead_suite;
                    let fut = read_one_chunk(
                        store, plugin_host, ch, idx, file_key, aead_suite, read_hedge,
                    );
                    inflight.push_back(Box::pin(fut));
                }
                if inflight.is_empty() {
                    break;
                }
                let next = inflight.next().await;
                match next {
                    Some(Ok(b)) => yield b,
                    Some(Err(e)) => Err(e)?,
                    None => break,
                }
            }
        };
        Ok(Box::pin(stream))
    }

    // ─── housekeeping ──────────────────────────────────────────────────────
    pub fn delete(&self, path: &str) -> Result<(), VfsError> {
        let _mk = self.vault.master_key().ok_or(VfsError::VaultLocked)?;
        let mut file = self
            .find_by_path(path)?
            .ok_or_else(|| VfsError::NotFound(path.into()))?;
        let device = self.sync.wal().device_id();
        let hlc = next_hlc(&self.sync);
        file.exists = LwwRegister::new(false, hlc, device);

        // Register shadows for each shard of each chunk (for chunked files).
        // Shadow records persist regardless of plugin reachability — that's
        // the "no silent leaks" invariant.
        let mut txn = Txn::new();
        if let Some(chunk_list) = file.chunk_list.clone() {
            for ch in &chunk_list {
                if let Some(chunk) = self.store.get_chunk(*ch)? {
                    for shard_id in &chunk.shard_list {
                        if let Some(shard) = self.store.get_shard(*shard_id)? {
                            let shadow = os_entities::Shadow {
                                shadow_id: os_types::ShadowId::new_v7(),
                                original_chunk_hash: *ch,
                                driver_id: shard.driver_id.value,
                                native_handle: shard.native_handle.value.clone(),
                                ciphertext_length: shard.ciphertext_length,
                                abandoned_at: Timestamp::from_string(now_iso()),
                                reason: os_entities::ShadowReason::DeletionOrphaned,
                                cached_elsewhere_risk: os_types::CachedElsewhereRisk::Low,
                                counts_against_quota: true,
                                tombstone_clears_at: None,
                            };
                            self.store.put_shadow(&mut txn, &shadow)?;
                        }
                    }
                }
            }
        }
        self.store.put_file(&mut txn, &file)?;
        self.store.commit(txn)?;
        Ok(())
    }

    /// F-FL-5: rename/move. Resolves `src` → FILE record by stable `file_id`,
    /// then writes `LwwRegister(file.path, dst)`. No tree mutation; the `path`
    /// field is a regular LWW field (DESIGN §5.8). Directory listings update
    /// implicitly via prefix projection (DESIGN §6.13).
    pub fn rename(&self, src: &str, dst: &str) -> Result<FileMeta, VfsError> {
        let _mk = self.vault.master_key().ok_or(VfsError::VaultLocked)?;
        let mut file = self
            .find_by_path(src)?
            .ok_or_else(|| VfsError::NotFound(src.into()))?;
        if !file.exists.value {
            return Err(VfsError::NotFound(src.into()));
        }
        let device = self.sync.wal().device_id();
        let hlc = next_hlc(&self.sync);
        file.path = LwwRegister::new(dst.to_string(), hlc, device);
        let mut txn = Txn::new();
        self.store.put_file(&mut txn, &file)?;
        self.store.commit(txn)?;
        Ok(FileMeta {
            file_id: file.file_id,
            path: file.path.value,
            size_bytes: file.size_bytes.value,
            modified_at: file.modified_at.value,
            content_type: file.content_type.value,
            exists: file.exists.value,
        })
    }

    /// F-SH-3 helper: bump a file's `file_key_version`, derive a fresh
    /// file_key, and re-encrypt the inline payload (if any) under it.
    /// Chunked payloads are flagged for async re-encryption — the spec
    /// says "heavy — async via repair scheduler" and the chunked rewrite
    /// is owned by `repair/`.
    pub fn rotate_file_key(&self, file_id: FileId) -> Result<u64, VfsError> {
        let mk = self.vault.master_key().ok_or(VfsError::VaultLocked)?;
        let mut file = self
            .store
            .get_file(file_id)?
            .ok_or_else(|| VfsError::NotFound(file_id.to_string()))?;
        let new_version = file.file_key_version + 1;
        if let Some(payload) = file.inline_payload.clone() {
            let old_key = derive_file_key(&mk, file_id, file.file_key_version)?;
            let pt = aead_decrypt(
                self.cfg.aead_suite,
                &old_key,
                &payload.nonce,
                &payload.ciphertext,
                &payload.tag,
                &inline_aad(file_id, file.file_key_version),
            )?;
            let new_key = derive_file_key(&mk, file_id, new_version)?;
            let nonce = random_nonce_12();
            let (ct, tag) = aead_encrypt(
                self.cfg.aead_suite,
                &new_key,
                &nonce,
                &pt,
                &inline_aad(file_id, new_version),
            )?;
            file.inline_payload = Some(InlineBlob {
                ciphertext: ct,
                nonce,
                tag,
            });
        }
        file.file_key_version = new_version;
        let mut txn = Txn::new();
        self.store.put_file(&mut txn, &file)?;
        self.store.commit(txn)?;
        Ok(new_version)
    }

    /// Read the current `file_key_version` for a file. Used by sharing to
    /// derive the file_key of a specific generation for KEM wrapping.
    pub fn file_key_version(&self, file_id: FileId) -> Result<u64, VfsError> {
        let f = self
            .store
            .get_file(file_id)?
            .ok_or_else(|| VfsError::NotFound(file_id.to_string()))?;
        Ok(f.file_key_version)
    }

    pub fn stat(&self, path: &str) -> Result<FileMeta, VfsError> {
        let f = self
            .find_by_path(path)?
            .ok_or_else(|| VfsError::NotFound(path.into()))?;
        if !f.exists.value {
            return Err(VfsError::NotFound(path.into()));
        }
        Ok(FileMeta {
            file_id: f.file_id,
            path: f.path.value,
            size_bytes: f.size_bytes.value,
            modified_at: f.modified_at.value,
            content_type: f.content_type.value,
            exists: f.exists.value,
        })
    }

    pub fn list(&self, prefix: &str) -> Result<Vec<FileMeta>, VfsError> {
        let mut out = Vec::new();
        for f in self.store.list_files_with_prefix(prefix)? {
            if f.exists.value {
                out.push(FileMeta {
                    file_id: f.file_id,
                    path: f.path.value,
                    size_bytes: f.size_bytes.value,
                    modified_at: f.modified_at.value,
                    content_type: f.content_type.value,
                    exists: f.exists.value,
                });
            }
        }
        Ok(out)
    }

    fn find_by_path(&self, path: &str) -> Result<Option<File>, VfsError> {
        Ok(self.store.get_file_by_path(path)?)
    }
}

/// Hedged-read implementation per DESIGN §6.4 / STATES_AND_FLOWS F-FL-1.
///
/// 1. Load all N shard records for the chunk.
/// 2. Filter to shards whose ack_state == Acked (Pending placeholders are
///    skipped; the chunk is implicitly Degraded if N_acked < N).
/// 3. Rank acked shards by `capacity_snapshot(Op::Get)` — most-ready first.
/// 4. Fire `K + read_hedge` parallel fetches against the top of the ranked
///    list. As fetches complete:
///     - On success → record bytes; if we already have K successful, drop
///       remaining inflight (race winner).
///     - On RateLimited / Unavailable / NotFound → replace with the next-
///       ranked shard's fetch, if any are still untried. Loop until we
///       have K successes or run out of candidates.
/// 5. Reconstruct the chunk from any K successful shards (EC handles
///    "fill the missing slots with None").
/// 6. AEAD verifies during reconstruct: if it fails, the chunk is
///    `LOST` (defense-in-depth) — bubble up. (Per-shard read-repair on
///    AEAD-tag-fail-of-individual-shard would require shard-level AEAD;
///    in this scheme AEAD is whole-chunk, so we surface the failure.)
async fn read_one_chunk(
    store: Arc<os_metadata::Store>,
    plugin_host: Arc<Host>,
    chunk_hash: ChunkHash,
    chunk_index: usize,
    file_key: os_crypto::SymKey,
    aead_suite: AeadSuite,
    read_hedge: usize,
) -> Result<Bytes, VfsError> {
    use os_plugin_host::Op;

    let chunk = store
        .get_chunk(chunk_hash)?
        .ok_or_else(|| VfsError::Metadata(format!("missing chunk {}", chunk_hash)))?;
    let n = chunk.ec_scheme.n as usize;
    let k = chunk.ec_scheme.k as usize;

    // Load shard metadata and select only Acked ones.
    let mut shards: Vec<Shard> = Vec::with_capacity(n);
    for shard_id in &chunk.shard_list {
        if let Some(s) = store.get_shard(*shard_id)? {
            if matches!(s.ack_state, AckState::Acked) {
                shards.push(s);
            }
        }
    }
    if shards.len() < k {
        return Err(VfsError::Plugin(format!(
            "chunk {} has only {} acked shards, need {} for reconstruct",
            chunk_hash,
            shards.len(),
            k
        )));
    }

    // Rank candidates by readiness on Op::Get.
    let provider_ids: Vec<ProviderId> = shards.iter().map(|s| s.driver_id.value).collect();
    let ranked = os_plugin_host::PoolDispatcher::rank(&plugin_host, Op::Get, &provider_ids).await;
    // Map ProviderId -> shard slot index in `chunk.shard_list` order so we
    // can place fetched bytes correctly for reconstruct.
    let slot_for_provider: std::collections::HashMap<ProviderId, usize> = chunk
        .shard_list
        .iter()
        .enumerate()
        .filter_map(|(slot, sid)| {
            shards
                .iter()
                .find(|s| s.shard_id == *sid)
                .map(|s| (s.driver_id.value, slot))
        })
        .collect();

    // Walk ranked candidates, firing up to K + read_hedge in parallel and
    // racing for the first K successes. Track which providers are
    // still-untried so we can replenish on failure.
    //
    // `ciphertext_length` is the *whole* AEAD ciphertext length (sum across
    // data shards before padding), NOT the per-shard size. For ChaCha20-
    // Poly1305 and AES-256-GCM the ciphertext length equals the plaintext
    // length (the 16-byte tag is carried separately in `Shard.encryption_tag`).
    // Using per-shard size here would truncate `ec_reconstruct` to ct/k
    // bytes for (k>1) parity schemes.
    let target = k + read_hedge;
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut nonce: Option<os_types::AeadNonce> = None;
    let mut tag: Option<os_types::AeadTag> = None;
    let ciphertext_length: u64 = chunk.plaintext_length;
    let mut successes = 0usize;
    let mut next_candidate = 0usize;
    let mut errors: Vec<String> = Vec::new();

    use futures::stream::{FuturesUnordered, StreamExt};
    type FetchFut = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = (ProviderId, Result<Vec<u8>, os_plugin_host::PluginError>),
                > + Send,
        >,
    >;
    let mut inflight: FuturesUnordered<FetchFut> = FuturesUnordered::new();

    fn make_fetch(
        plugin_host: Arc<Host>,
        provider_id: ProviderId,
        handle: os_entities::NativeHandle,
    ) -> FetchFut {
        Box::pin(async move {
            let plugin = match plugin_host.get_chunk(provider_id) {
                Ok(p) => p,
                Err(e) => return (provider_id, Err(e)),
            };
            let r = plugin.get(&handle, None).await;
            (provider_id, r)
        })
    }

    // Initial K + H fan-out.
    while inflight.len() < target && next_candidate < ranked.len() {
        let pid = ranked[next_candidate].provider_id;
        next_candidate += 1;
        if let Some(s) = shards.iter().find(|s| s.driver_id.value == pid) {
            inflight.push(make_fetch(
                plugin_host.clone(),
                s.driver_id.value,
                s.native_handle.value.clone(),
            ));
        }
    }

    while successes < k {
        let next = match inflight.next().await {
            Some(v) => v,
            None => {
                return Err(VfsError::Plugin(format!(
                    "chunk {} read failed: only {} of {} shards usable; errors: {}",
                    chunk_hash,
                    successes,
                    k,
                    errors.join("; ")
                )));
            }
        };
        match next {
            (provider_id, Ok(bytes)) => {
                if let Some(slot) = slot_for_provider.get(&provider_id) {
                    if shard_data[*slot].is_none() {
                        shard_data[*slot] = Some(bytes);
                        if let Some(s) = shards.iter().find(|s| s.driver_id.value == provider_id) {
                            nonce.get_or_insert(s.encryption_nonce.clone());
                            tag.get_or_insert(s.encryption_tag);
                        }
                        successes += 1;
                    }
                }
            }
            (provider_id, Err(e)) => {
                tracing::warn!(
                    chunk = %chunk_hash, %provider_id, ?e,
                    "shard fetch failed; falling back"
                );
                errors.push(format!("{provider_id}: {e}"));
                // Replenish from the next-ranked untried candidate so the
                // race continues with a full set of fetches in flight.
                while next_candidate < ranked.len() {
                    let pid = ranked[next_candidate].provider_id;
                    next_candidate += 1;
                    if let Some(s) = shards.iter().find(|s| s.driver_id.value == pid) {
                        inflight.push(make_fetch(
                            plugin_host.clone(),
                            s.driver_id.value,
                            s.native_handle.value.clone(),
                        ));
                        break;
                    }
                }
            }
        }
    }

    // Drop remaining inflight requests — race winners declared.
    drop(inflight);

    let chunk_key = derive_chunk_key(&file_key, chunk_index as u64)?;
    let pt = reconstruct_and_decrypt(
        shard_data,
        chunk_hash,
        &chunk_key,
        nonce.as_ref().expect("nonce captured"),
        tag.as_ref().expect("tag captured"),
        aead_suite,
        chunk.ec_scheme,
        ciphertext_length,
    )?;
    Ok(Bytes::from(pt))
}

fn group_lookup(
    pool: &os_placement::PoolSnapshot,
    picks: &[(u8, ProviderId)],
) -> std::collections::BTreeMap<ProviderId, os_types::TrustCorrelationGroup> {
    let mut out = std::collections::BTreeMap::new();
    for (_, id) in picks {
        if let Some(entry) = pool.providers.iter().find(|p| p.provider_id == *id) {
            out.insert(*id, entry.trust_group.clone());
        }
    }
    out
}

/// AAD for inline file payloads. Bound to `(file_id, file_key_version)` —
/// the version makes ciphertext from a previous key generation
/// non-decryptable after F-SH-3 rotates.
fn inline_aad(file_id: FileId, file_key_version: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 16 + 8);
    v.extend_from_slice(b"inline:");
    v.extend_from_slice(file_id.as_uuid().as_bytes());
    v.extend_from_slice(&file_key_version.to_be_bytes());
    v
}

/// Derive the per-file symmetric key. Bound to MK + file_id +
/// file_key_version. Sharing exposes this same key to recipients via KEM
/// wrap; revocation bumps the version so revoked recipients lose access.
pub fn derive_file_key(
    mk: &os_crypto::SymKey,
    file_id: FileId,
    version: u64,
) -> Result<os_crypto::SymKey, os_crypto::CryptoError> {
    let mut info = Vec::with_capacity(16 + 8);
    info.extend_from_slice(file_id.as_uuid().as_bytes());
    info.extend_from_slice(&version.to_be_bytes());
    derive_subkey(mk, KeyPurpose::FILE, Some(&info))
}

fn next_hlc(sync: &SyncEngine) -> Hlc {
    let cur = sync.wal().current_hlc();
    if cur == Hlc::ZERO {
        Hlc::new(1, 0)
    } else {
        cur
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

// Suppress unused import warnings for code paths still in skeleton form.
#[allow(dead_code)]
fn _bind_shard_id(_: ShardId) {}

#[cfg(test)]
mod redundancy_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use os_crypto::generate_keypair;
    use os_metadata::backend::MemoryBackend;
    use os_plugin_host::{Host, LocalDirPlugin};
    use os_types::{DeviceId, VaultId};
    use os_wal::WalBuilder;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn fixture_with_local_plugin() -> (Arc<VfsService>, ProviderId, std::path::PathBuf) {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());

        // Local-dir chunk plugin.
        let mut plugin_dir = std::env::temp_dir();
        plugin_dir.push(format!("os-vfs-plugin-{}", uuid::Uuid::now_v7()));
        let local = LocalDirPlugin::new(&plugin_dir).unwrap();
        let provider_id = ProviderId::new_v7();
        host.register_chunk(provider_id, Arc::new(local));

        // Persist a Provider record so placement sees the pool.
        let provider = os_entities::Provider {
            provider_id,
            plugin_id: os_types::PluginId::new("org.openstorage.local"),
            instance_label: "local".into(),
            credentials_handle: os_types::CredentialsHandle::new(vec![]).unwrap(),
            capabilities: os_types::CapabilitySet::default(),
            legal_class: os_types::LegalClass::Green,
            trust_correlation_group: os_types::TrustCorrelationGroup::new("local"),
            quota: os_types::QuotaState {
                total: None,
                used: None,
                untrusted: false,
            },
            rate_limit: os_types::RateLimitState {
                remaining: u32::MAX,
                reset_at: Timestamp::from_string("now"),
            },
            health: HealthScore::new(1.0),
            latency: os_types::LatencyProfile::default(),
            untrusted_quota: false,
        };
        let mut txn = Txn::new();
        store.put_provider(&mut txn, &provider).unwrap();
        store.commit(txn).unwrap();

        let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
        vault.set_unlocked(VaultId::new_v7(), [9u8; 32]).unwrap();

        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-vfs-wal-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tdir).unwrap();
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(tdir.join("wal.bin"))
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        let sync = Arc::new(SyncEngine::new(Arc::new(wal)));

        let svc = Arc::new(VfsService::with_host(
            store,
            vault,
            sync,
            host,
            VfsConfig {
                inline_threshold_bytes: 256,
                chunk_bytes: 64 * 1024,
                aead_suite: AeadSuite::ChaCha20Poly1305,
                ec_targets: EcTargets { k_target: 1, n_max: 13 },
                read_hedge: 0,
                chunk_upload_concurrency: 4,
                chunk_fetch_concurrency: 4,
            },
        ));
        (svc, provider_id, plugin_dir)
    }

    #[tokio::test]
    async fn inline_round_trip() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        let m = svc.write("/x.txt", b"hello").await.unwrap();
        assert_eq!(m.size_bytes, 5);
        let got = svc.read("/x.txt").await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn chunked_round_trip_above_threshold() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        // 200 KiB random payload → 4 chunks at 64 KiB.
        let mut payload = vec![0u8; 200 * 1024];
        rand::thread_rng().fill_bytes(&mut payload);
        let m = svc.write("/big", &payload).await.unwrap();
        assert_eq!(m.size_bytes as usize, payload.len());
        let got = svc.read("/big").await.unwrap();
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    /// F-FL-5 — rename moves a file's path and the old path no longer
    /// resolves; the file_id stays stable; content is preserved.
    #[tokio::test]
    async fn rename_inline_file() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        let original = svc.write("/old.txt", b"hello").await.unwrap();
        let renamed = svc.rename("/old.txt", "/new.txt").unwrap();
        assert_eq!(renamed.file_id, original.file_id);
        assert_eq!(renamed.path, "/new.txt");
        assert!(matches!(svc.stat("/old.txt"), Err(VfsError::NotFound(_))));
        let got = svc.read("/new.txt").await.unwrap();
        assert_eq!(got, b"hello");
    }

    /// F-FL-5 — chunked file rename preserves chunk_list; content readable.
    #[tokio::test]
    async fn rename_chunked_file() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        let payload = vec![3u8; 200 * 1024];
        let original = svc.write("/big-old", &payload).await.unwrap();
        let renamed = svc.rename("/big-old", "/big-new").unwrap();
        assert_eq!(renamed.file_id, original.file_id);
        assert!(matches!(svc.stat("/big-old"), Err(VfsError::NotFound(_))));
        let got = svc.read("/big-new").await.unwrap();
        assert_eq!(got, payload);
    }

    /// F-FL-5 — listing with the destination prefix surfaces the renamed
    /// file; listing with the source prefix does not.
    #[tokio::test]
    async fn rename_updates_prefix_listing() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        svc.write("/inbox/a.txt", b"a").await.unwrap();
        svc.rename("/inbox/a.txt", "/archive/a.txt").unwrap();
        let inbox = svc.list("/inbox/").unwrap();
        assert!(inbox.iter().all(|f| f.path != "/inbox/a.txt"));
        let archive = svc.list("/archive/").unwrap();
        assert!(archive.iter().any(|f| f.path == "/archive/a.txt"));
    }

    /// F-FL-5 — renaming a missing path returns NotFound.
    #[tokio::test]
    async fn rename_missing_returns_not_found() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        assert!(matches!(svc.rename("/missing", "/wherever"), Err(VfsError::NotFound(_))));
    }

    #[tokio::test]
    async fn streaming_read_yields_chunks() {
        let (svc, _pid, _) = fixture_with_local_plugin();
        let payload = vec![7u8; 200 * 1024];
        svc.write("/big", &payload).await.unwrap();
        let mut s = svc.read_stream("/big").await.unwrap();
        use futures::StreamExt;
        let mut count = 0;
        let mut total = 0;
        while let Some(c) = s.next().await {
            let c = c.unwrap();
            total += c.len();
            count += 1;
        }
        assert_eq!(total, payload.len());
        assert!(count >= 3, "expected at least 3 stream items, got {count}");
    }
}
