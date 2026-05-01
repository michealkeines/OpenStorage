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
use os_placement::{pick_shards_for_chunk, DiversityPolicy};
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
    pub ec_scheme: ECScheme,
}

impl Default for VfsConfig {
    fn default() -> Self {
        Self {
            inline_threshold_bytes: 16 * 1024,
            chunk_bytes: 4 * 1024 * 1024,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            ec_scheme: ECScheme { k: 1, n: 1 },
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
        let file_key = derive_subkey(&mk, KeyPurpose::FILE, Some(path.as_bytes()))?;
        let vault_salt: Option<Vec<u8>> = self
            .vault
            .vault_id()
            .and_then(|_| self.vault.master_key())
            .map(|mk| {
                derive_subkey(&mk, KeyPurpose::VAULT_SALT, None)
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default()
            });

        let mut chunk_list: Vec<ChunkHash> = Vec::new();
        let mut total_size: u64 = 0;

        let mut leftover: Vec<u8> = head;
        let mut chunk_index: u64 = 0;
        loop {
            // Build one full chunk: combine leftover + read more until target chunk size.
            let mut chunk_buf = std::mem::take(&mut leftover);
            chunk_buf.reserve(self.cfg.chunk_bytes.saturating_sub(chunk_buf.len()));
            while chunk_buf.len() < self.cfg.chunk_bytes {
                let want = self.cfg.chunk_bytes - chunk_buf.len();
                let mut tmp = vec![0u8; want];
                let read = reader
                    .read(&mut tmp)
                    .await
                    .map_err(|e| VfsError::Io(e.to_string()))?;
                if read == 0 {
                    break;
                }
                chunk_buf.extend_from_slice(&tmp[..read]);
            }
            if chunk_buf.is_empty() {
                break;
            }
            // Position-salted chunk hash: include `chunk_index` so identical
            // payloads at different positions don't collide. Cross-position
            // dedup will land when content-addressed keys come in (DESIGN
            // §7); for the baseline we keep distinct records per position.
            let mut salted = Vec::with_capacity(8 + vault_salt.as_deref().map_or(0, |s| s.len()));
            salted.extend_from_slice(&chunk_index.to_be_bytes());
            if let Some(s) = vault_salt.as_deref() {
                salted.extend_from_slice(s);
            }
            let chunk_h = chunk_hash_bytes(&chunk_buf, Some(&salted));
            let chunk_key = derive_chunk_key(&file_key, chunk_index)?;
            self.persist_chunk(chunk_h, chunk_index, &chunk_buf, &chunk_key).await?;
            chunk_list.push(chunk_h);
            total_size += chunk_buf.len() as u64;
            chunk_index += 1;
            if chunk_buf.len() < self.cfg.chunk_bytes {
                break; // EOF reached partway through this chunk
            }
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
        let file_key = derive_subkey(mk, KeyPurpose::FILE, Some(path.as_bytes()))?;
        let aad = inline_aad(file_id, path);
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
    async fn persist_chunk(
        &self,
        chunk_h: ChunkHash,
        chunk_index: u64,
        plaintext: &[u8],
        chunk_key: &os_crypto::SymKey,
    ) -> Result<(), VfsError> {
        let _ = chunk_index;
        let scheme = self.cfg.ec_scheme;
        let enc = encrypt_and_encode(plaintext, chunk_h, chunk_key, self.cfg.aead_suite, scheme, None)?;

        // Pick providers from current pool.
        let pool = self.vault.current_pool()?;
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

        // For every placement-picked primary, build a fallback list of
        // providers in the *same* trust group (preserves diversity since the
        // shard still ends up in that group). The dispatcher picks the most-
        // ready candidate at call time, so a rate-limited primary doesn't
        // block the chunk — the bytes flow to a sibling and the resulting
        // Shard.driver_id reflects who actually accepted them.
        let primary_groups = group_lookup(&pool, &picks);
        let mut already_used: std::collections::BTreeSet<os_types::TrustCorrelationGroup> =
            std::collections::BTreeSet::new();
        let mut shard_records: Vec<(Shard, ProviderId)> = Vec::with_capacity(picks.len());
        for (es, (shard_index, primary_id)) in enc.shards.iter().zip(picks.iter()) {
            let group = primary_groups
                .get(primary_id)
                .cloned()
                .unwrap_or_else(|| os_types::TrustCorrelationGroup::new("unknown"));
            // Candidates: primary first, then siblings in the same group.
            // Skip groups already used by other shards if diversity is on
            // (defensive — placement should already have ensured distinct
            // groups across shards, but if it can't pick this one again we
            // keep the invariant locally).
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

            let dispatched = os_plugin_host::PoolDispatcher::put_with_fallback(
                &self.plugin_host,
                &candidates,
                &es.ciphertext,
                &PutHint::default(),
                os_plugin_host::DispatcherConfig::default(),
            )
            .await?;
            already_used.insert(group);

            shard_records.push((
                Shard {
                    shard_id: es.shard_id,
                    chunk_hash: chunk_h,
                    shard_index: *shard_index,
                    encryption_nonce: enc.nonce.clone(),
                    encryption_tag: enc.tag,
                    ciphertext_length: es.ciphertext.len() as u64,
                    driver_id: os_entities::LwwSet::new(
                        dispatched.provider_id,
                        None,
                        next_hlc(&self.sync),
                        self.sync.wal().device_id(),
                    ),
                    native_handle: os_entities::LwwSet::new(
                        dispatched.handle,
                        None,
                        next_hlc(&self.sync),
                        self.sync.wal().device_id(),
                    ),
                    stored_at: Timestamp::from_string(now_iso()),
                    last_verified_at: Timestamp::from_string(now_iso()),
                    health_score: HealthScore::new(1.0),
                    ack_state: AckState::Acked,
                },
                dispatched.provider_id,
            ));
        }

        let chunk = Chunk {
            chunk_hash: chunk_h,
            plaintext_length: enc.plaintext_length,
            ec_scheme: scheme,
            shard_list: shard_records.iter().map(|(s, _)| s.shard_id).collect(),
            refcount: os_entities::Counter::default(),
            replication_state: ReplicationState::Full,
            last_scrubbed_at: Timestamp::from_string(now_iso()),
            access_count_window: os_entities::Counter::default(),
            tier: Tier::Hot,
        };
        let mut txn = Txn::new();
        self.store.put_chunk(&mut txn, &chunk)?;
        for (s, _) in &shard_records {
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
            let file_key = derive_subkey(&mk, KeyPurpose::FILE, Some(path_owned.as_bytes()))?;
            let aad = inline_aad(file.file_id, &path_owned);
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
        let file_key = derive_subkey(&mk, KeyPurpose::FILE, Some(path_owned.as_bytes()))?;
        let stream = async_stream::try_stream! {
            for (idx, ch) in chunk_list.iter().enumerate() {
                let chunk = store
                    .get_chunk(*ch)?
                    .ok_or_else(|| VfsError::Metadata(format!("missing chunk {}", ch)))?;
                let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; chunk.ec_scheme.n as usize];
                let mut nonce: Option<os_types::AeadNonce> = None;
                let mut tag: Option<os_types::AeadTag> = None;
                let mut ciphertext_length: u64 = 0;
                for (si, shard_id) in chunk.shard_list.iter().enumerate() {
                    let shard = store
                        .get_shard(*shard_id)?
                        .ok_or_else(|| VfsError::Metadata(format!("missing shard {}", shard_id)))?;
                    let provider_id = shard.driver_id.value;
                    let handle = shard.native_handle.value.clone();
                    let plugin = plugin_host.get_chunk(provider_id)?;
                    let bytes = plugin.get(&handle, None).await?;
                    shard_data[si] = Some(bytes);
                    nonce.get_or_insert(shard.encryption_nonce.clone());
                    tag.get_or_insert(shard.encryption_tag);
                    ciphertext_length = ciphertext_length.max(shard.ciphertext_length);
                }
                let chunk_key = derive_chunk_key(&file_key, idx as u64)?;
                let pt = reconstruct_and_decrypt(
                    shard_data,
                    *ch,
                    &chunk_key,
                    nonce.as_ref().expect("nonce captured"),
                    tag.as_ref().expect("tag captured"),
                    cfg.aead_suite,
                    chunk.ec_scheme,
                    ciphertext_length,
                )?;
                yield Bytes::from(pt);
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

    pub fn stat(&self, path: &str) -> Result<FileMeta, VfsError> {
        let f = self
            .find_by_path(path)?
            .ok_or_else(|| VfsError::NotFound(path.into()))?;
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
        for f in self.store.iter_files()? {
            if f.exists.value && f.path.value.starts_with(prefix) {
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
        for f in self.store.iter_files()? {
            if f.path.value == path {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }
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

fn inline_aad(file_id: FileId, path: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 16 + path.len());
    v.extend_from_slice(b"inline:");
    v.extend_from_slice(file_id.as_uuid().as_bytes());
    v.extend_from_slice(path.as_bytes());
    v
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
                ec_scheme: ECScheme { k: 1, n: 1 },
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
