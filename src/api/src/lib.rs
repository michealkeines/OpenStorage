//! os-api — local HTTP/2 API server.
//!
//! Vertical slice exposed in this iteration:
//! - `POST /v1/vaults` — create a vault from a passphrase
//! - `POST /v1/vaults/{vault_id}/unlock` — unlock with a passphrase
//! - `POST /v1/vaults/{vault_id}/lock` — lock
//! - `PUT /v1/vaults/{vault_id}/files/{*path}` — write file (inline)
//! - `GET /v1/vaults/{vault_id}/files/{*path}` — read file
//! - `HEAD /v1/vaults/{vault_id}/files/{*path}` — stat
//! - `DELETE /v1/vaults/{vault_id}/files/{*path}` — delete
//! - `GET /v1/vaults/{vault_id}/dirs?prefix=...` — list

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::TryStreamExt;
use tokio_util::io::StreamReader;
use serde::{Deserialize, Serialize};

use os_events::EventBus;
use os_identity::IdentityService;
use os_lease::LeaseService;
use os_plugin_host::Host;
use os_recovery::RecoveryService;
use os_repair::RepairScheduler;
use os_types::VaultId;
use os_vault::VaultManager;
use os_vfs::VfsService;

#[derive(Clone)]
pub struct AppState {
    pub recovery: Arc<RecoveryService>,
    pub vault: Arc<VaultManager>,
    pub vfs: Arc<VfsService>,
    pub identity: Arc<IdentityService>,
    pub lease: Arc<LeaseService>,
    pub repair: Arc<RepairScheduler>,
    pub events: Arc<EventBus>,
    pub host: Arc<Host>,
    pub device_id: os_types::DeviceId,
    /// Optional fault handle for integration tests.
    pub fault: Option<FaultHandleAny>,
    /// Plugin-state registry; tracks Loaded/Active/Paused/Disabled per provider.
    pub plugin_states: Arc<std::sync::RwLock<std::collections::HashMap<os_types::ProviderId, PluginState>>>,
}

/// Type-erased fault handle. The concrete type is `os_plugin_fault_inject::FaultHandle`.
#[derive(Clone)]
pub struct FaultHandleAny {
    pub fail_puts: Arc<dyn Fn(u32) + Send + Sync>,
    pub fail_gets: Arc<dyn Fn(u32) + Send + Sync>,
    pub corrupt_gets: Arc<dyn Fn(u32) + Send + Sync>,
    pub pause: Arc<dyn Fn() + Send + Sync>,
    pub resume: Arc<dyn Fn() + Send + Sync>,
    pub clear: Arc<dyn Fn() + Send + Sync>,
    pub snapshot: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginState {
    Loaded,
    Init,
    Ready,
    Active,
    Paused,
    Disabled,
    Closed,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/system/status", get(system_status))
        .route("/v1/system/events", get(events_tail))
        .route("/v1/vaults", post(create_vault))
        .route(
            "/v1/vaults/:vault_id",
            axum::routing::delete(destroy_vault),
        )
        .route("/v1/vaults/:vault_id/unlock", post(unlock_vault))
        .route("/v1/vaults/:vault_id/lock", post(lock_vault))
        .route("/v1/vaults/:vault_id/rotate-mk", post(rotate_mk))
        .route("/v1/vaults/:vault_id/identity", get(get_identity))
        .route(
            "/v1/vaults/:vault_id/identity/rotate",
            post(rotate_identity_route),
        )
        .route(
            "/v1/vaults/:vault_id/recovery",
            get(get_recovery),
        )
        .route(
            "/v1/vaults/:vault_id/recovery/rotate-token",
            post(rotate_token_route),
        )
        .route(
            "/v1/vaults/:vault_id/lease",
            get(get_lease)
                .post(acquire_lease)
                .delete(release_lease),
        )
        .route("/v1/vaults/:vault_id/lease/renew", post(renew_lease))
        .route("/v1/vaults/:vault_id/wal", get(get_wal))
        .route("/v1/vaults/:vault_id/snapshot", get(get_snapshot))
        .route("/v1/vaults/:vault_id/providers", get(list_providers))
        .route("/v1/vaults/:vault_id/peers", get(list_peers))
        .route("/v1/vaults/:vault_id/shadows", get(list_shadows))
        .route(
            "/v1/vaults/:vault_id/repair",
            get(get_repair).post(enqueue_repair),
        )
        .route(
            "/v1/vaults/:vault_id/shares",
            get(list_shares).post(create_share),
        )
        .route(
            "/v1/vaults/:vault_id/shares/:share_id",
            axum::routing::delete(revoke_share),
        )
        .route("/v1/vaults/:vault_id/snapshot/push", post(push_snapshot_route))
        .route(
            "/v1/vaults/:vault_id/files/*path",
            get(get_file)
                .put(put_file)
                .patch(patch_file)
                .post(move_file)
                .head(head_file)
                .delete(delete_file),
        )
        .route("/v1/vaults/:vault_id/dirs", get(list_dir))
        .route("/v1/system/fault", get(get_fault).post(set_fault).delete(clear_fault))
        .route(
            "/v1/vaults/:vault_id/providers/:provider_id/state",
            get(get_provider_state).post(set_provider_state),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct StatusResp {
    state: &'static str,
    vault_id: Option<String>,
}

async fn system_status(State(s): State<AppState>) -> Json<StatusResp> {
    let state = match s.vault.state() {
        os_vault::VaultState::Uncreated => "uncreated",
        os_vault::VaultState::Locked => "locked",
        os_vault::VaultState::Unlocking => "unlocking",
        os_vault::VaultState::Unlocked => "unlocked",
        os_vault::VaultState::Locking => "locking",
        os_vault::VaultState::Destroying => "destroying",
        os_vault::VaultState::Destroyed => "destroyed",
    };
    Json(StatusResp {
        state,
        vault_id: s.vault.vault_id().map(|v| v.to_string()),
    })
}

#[derive(Deserialize)]
struct CreateVaultReq {
    passphrase: String,
}

#[derive(Serialize)]
struct CreateVaultResp {
    vault_id: String,
}

async fn create_vault(
    State(s): State<AppState>,
    Json(req): Json<CreateVaultReq>,
) -> Result<Json<CreateVaultResp>, ApiError> {
    let (v, _m) = s
        .recovery
        .new_vault(req.passphrase.as_bytes())
        .map_err(|e| ApiError::bad(format!("create_vault: {e}")))?;
    Ok(Json(CreateVaultResp {
        vault_id: v.vault_id.to_string(),
    }))
}

#[derive(Deserialize)]
struct UnlockReq {
    passphrase: String,
}

async fn unlock_vault(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    Json(req): Json<UnlockReq>,
) -> Result<StatusCode, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    s.recovery
        .unlock(v, req.passphrase.as_bytes())
        .map_err(|e| ApiError::unauth(format!("unlock: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn lock_vault(State(s): State<AppState>) -> Result<StatusCode, ApiError> {
    s.vault
        .lock()
        .map_err(|e| ApiError::bad(format!("lock: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
    request: Request,
) -> Result<impl IntoResponse, ApiError> {
    let path = format!("/{path}");
    let size_hint = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let body_stream = request
        .into_body()
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    let reader = StreamReader::new(body_stream);
    let meta = s
        .vfs
        .write_stream(&path, reader, size_hint)
        .await
        .map_err(|e| match e {
            os_vfs::VfsError::VaultLocked => ApiError::locked(format!("write: {e}")),
            other => ApiError::bad(format!("write: {other}")),
        })?;
    Ok((
        StatusCode::OK,
        Json(FileMetaJson {
            file_id: meta.file_id.to_string(),
            path: meta.path,
            size_bytes: meta.size_bytes,
            modified_at: meta.modified_at.0.clone(),
            content_type: meta.content_type,
        }),
    ))
}

async fn get_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let path = format!("/{path}");
    // We need both the size header and a stream. Stat first for the size,
    // then start the stream.
    let meta = s.vfs.stat(&path).map_err(|e| match e {
        os_vfs::VfsError::NotFound(_) => ApiError::not_found(format!("read: {e}")),
        other => ApiError::bad(format!("read: {other}")),
    })?;
    let stream = s.vfs.read_stream(&path).await.map_err(|e| match e {
        os_vfs::VfsError::NotFound(_) => ApiError::not_found(format!("read: {e}")),
        os_vfs::VfsError::VaultLocked => ApiError::locked(format!("read: {e}")),
        other => ApiError::bad(format!("read: {other}")),
    })?;
    let mapped = stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    let body = Body::from_stream(mapped);
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Length",
        HeaderValue::from_str(&meta.size_bytes.to_string()).unwrap(),
    );
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, body))
}

async fn head_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let path = format!("/{path}");
    let meta = s
        .vfs
        .stat(&path)
        .map_err(|e| ApiError::not_found(format!("stat: {e}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Size-Bytes",
        HeaderValue::from_str(&meta.size_bytes.to_string()).unwrap(),
    );
    headers.insert(
        "X-File-Id",
        HeaderValue::from_str(&meta.file_id.to_string()).unwrap(),
    );
    Ok((StatusCode::OK, headers))
}

/// F-FL-5 Rename/Move. Route shape: `POST /v1/vaults/{v}/files/{src}/move`
/// with body `{ "to": "/dst" }`. The wildcard `*path` captures `<src>/move`;
/// we strip the trailing `/move` segment to recover the source path.
#[derive(Deserialize)]
struct MoveReq {
    to: String,
}

async fn move_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
    Json(req): Json<MoveReq>,
) -> Result<Json<FileMetaJson>, ApiError> {
    let path = format!("/{path}");
    let src = path
        .strip_suffix("/move")
        .ok_or_else(|| ApiError::bad("move requires URL ending in /move"))?;
    if src.is_empty() {
        return Err(ApiError::bad("source path is empty"));
    }
    let dst = if req.to.starts_with('/') {
        req.to
    } else {
        format!("/{}", req.to)
    };
    let meta = s.vfs.rename(src, &dst).map_err(|e| match e {
        os_vfs::VfsError::NotFound(_) => ApiError::not_found(format!("rename: {e}")),
        os_vfs::VfsError::VaultLocked => ApiError::locked(format!("rename: {e}")),
        other => ApiError::bad(format!("rename: {other}")),
    })?;
    Ok(Json(FileMetaJson {
        file_id: meta.file_id.to_string(),
        path: meta.path,
        size_bytes: meta.size_bytes,
        modified_at: meta.modified_at.0.clone(),
        content_type: meta.content_type,
    }))
}

/// F-FL-3 Partial write. Per STATES_AND_FLOWS §2.2 F-FL-3: same as F-FL-2 but
/// only re-encrypts affected chunks. Baseline implementation here splices the
/// supplied range into the existing plaintext and re-writes the file via the
/// normal write path. The chunk-granular optimization is an internal detail
/// that doesn't change the API contract.
async fn patch_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
    request: Request,
) -> Result<impl IntoResponse, ApiError> {
    let path = format!("/{path}");
    let cr = request
        .headers()
        .get("content-range")
        .ok_or_else(|| ApiError::bad("PATCH requires Content-Range header"))?
        .to_str()
        .map_err(|_| ApiError::bad("invalid Content-Range header"))?
        .to_string();
    let (start, end, total) = parse_content_range(&cr)?;
    let body_bytes = axum::body::to_bytes(request.into_body(), 64 * 1024 * 1024)
        .await
        .map_err(|e| ApiError::bad(format!("read body: {e}")))?;
    let expected_len = end - start + 1;
    if body_bytes.len() as u64 != expected_len {
        return Err(ApiError::bad(format!(
            "body length {} does not match Content-Range span {}",
            body_bytes.len(),
            expected_len
        )));
    }

    // Read existing plaintext (file must exist; PATCH is not a creator).
    let mut current = match s.vfs.read(&path).await {
        Ok(b) => b,
        Err(os_vfs::VfsError::VaultLocked) => {
            return Err(ApiError::locked("patch: vault locked"));
        }
        Err(os_vfs::VfsError::NotFound(_)) => {
            return Err(ApiError::not_found("patch: file not found"));
        }
        Err(e) => return Err(ApiError::bad(format!("patch: {e}"))),
    };
    if (current.len() as u64) < total && (total as usize) > current.len() {
        current.resize(total as usize, 0);
    }
    let s_idx = start as usize;
    let e_idx = (end + 1) as usize;
    if e_idx > current.len() {
        current.resize(e_idx.max(total as usize), 0);
    }
    current[s_idx..e_idx].copy_from_slice(&body_bytes);
    if (current.len() as u64) > total {
        current.truncate(total as usize);
    }

    let meta = s
        .vfs
        .write(&path, &current)
        .await
        .map_err(|e| ApiError::bad(format!("patch: {e}")))?;
    Ok((
        StatusCode::OK,
        Json(FileMetaJson {
            file_id: meta.file_id.to_string(),
            path: meta.path,
            size_bytes: meta.size_bytes,
            modified_at: meta.modified_at.0.clone(),
            content_type: meta.content_type,
        }),
    ))
}

/// Parse a `Content-Range: bytes <start>-<end>/<total>` header.
fn parse_content_range(s: &str) -> Result<(u64, u64, u64), ApiError> {
    let s = s.trim();
    let rest = s
        .strip_prefix("bytes ")
        .ok_or_else(|| ApiError::bad("Content-Range must start with 'bytes '"))?;
    let (range, total) = rest
        .split_once('/')
        .ok_or_else(|| ApiError::bad("Content-Range missing '/total'"))?;
    let total: u64 = total
        .parse()
        .map_err(|_| ApiError::bad("Content-Range total not a number"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| ApiError::bad("Content-Range missing '-'"))?;
    let start: u64 = start
        .parse()
        .map_err(|_| ApiError::bad("Content-Range start not a number"))?;
    let end: u64 = end
        .parse()
        .map_err(|_| ApiError::bad("Content-Range end not a number"))?;
    if end < start {
        return Err(ApiError::bad("Content-Range end < start"));
    }
    if end >= total {
        return Err(ApiError::bad("Content-Range end >= total"));
    }
    Ok((start, end, total))
}

async fn delete_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let path = format!("/{path}");
    // Capture chunk_list before delete so we can enqueue GC sweeps for the
    // shards that are about to lose their last referer.
    let chunks: Vec<os_types::ChunkHash> = match s.vfs.stat(&path) {
        Ok(_) => {
            let backend = s.vault.store().backend();
            let mut out = Vec::new();
            for kv in backend
                .scan_prefix(os_metadata::ColumnFamily::Files, b"")
                .map_err(|e| ApiError::bad(format!("scan: {e}")))?
            {
                let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
                let f: os_entities::File = ciborium::from_reader(&v[..])
                    .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
                if f.path.value == path {
                    if let Some(cl) = f.chunk_list {
                        out.extend(cl);
                    }
                    break;
                }
            }
            out
        }
        Err(_) => Vec::new(),
    };
    s.vfs
        .delete(&path)
        .map_err(|e| ApiError::not_found(format!("delete: {e}")))?;
    for ch in chunks {
        let _ = s.repair.enqueue(os_repair::RepairTask {
            chunk_hash: ch,
            priority: 5,
            source: os_repair::RepairSource::GcSweep,
            attempt: 0,
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

async fn list_dir(
    State(s): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<FileMetaJson>>, ApiError> {
    let prefix = q.prefix.unwrap_or_else(|| "/".into());
    let metas = s
        .vfs
        .list(&prefix)
        .map_err(|e| ApiError::bad(format!("list: {e}")))?;
    Ok(Json(
        metas
            .into_iter()
            .map(|m| FileMetaJson {
                file_id: m.file_id.to_string(),
                path: m.path,
                size_bytes: m.size_bytes,
                modified_at: m.modified_at.0,
                content_type: m.content_type,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct FileMetaJson {
    file_id: String,
    path: String,
    size_bytes: u64,
    modified_at: String,
    content_type: String,
}

fn parse_vault_id(s: &str) -> Result<VaultId, ApiError> {
    let u = uuid::Uuid::parse_str(s).map_err(|_| ApiError::bad("invalid vault_id"))?;
    Ok(VaultId::from_uuid(u))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    fn unauth(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }
    fn locked(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(423).unwrap(),
            message: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}

// ─── new handlers: state inspection + mutation ─────────────────────────────

async fn destroy_vault(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    if headers.get("x-confirm-destroy").map(|v| v.as_bytes()) != Some(b"yes") {
        return Err(ApiError::bad(
            "destroy requires header x-confirm-destroy: yes",
        ));
    }
    let v = parse_vault_id(&vault_id)?;
    let report = s
        .recovery
        .destroy_vault(v)
        .await
        .map_err(|e| ApiError::bad(format!("destroy: {e}")))?;
    Ok(Json(serde_json::json!({
        "vault_id": v.to_string(),
        "removed_shards": report.removed_shards,
        "failed_shards": report.failed_shards,
        "unknown_shards": report.unknown_shards,
        "state": "destroyed",
    })))
}

#[derive(Deserialize)]
struct RotateMkReq {
    new_passphrase: String,
}

async fn rotate_mk(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    Json(req): Json<RotateMkReq>,
) -> Result<StatusCode, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    s.recovery
        .rotate_master_key(v, req.new_passphrase.as_bytes())
        .map_err(|e| ApiError::bad(format!("rotate-mk: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_identity(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = s.identity.store();
    let mut idents = Vec::new();
    let backend = store.backend();
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Identity, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let id: os_entities::Identity = ciborium::from_reader(&v[..])
            .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
        idents.push(serde_json::json!({
            "identity_id": id.identity_id.0,
            "epoch_count": id.epochs.len(),
            "current_epoch": id.epochs.last().map(|e| e.epoch.0),
            "anchor_fingerprint": hex::encode(id.epochs.first().map(|e| e.fingerprint.0).unwrap_or_default()),
        }));
    }
    Ok(Json(serde_json::json!({ "identities": idents })))
}

async fn rotate_identity_route(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Find the only identity (single-user vault).
    let store = s.identity.store();
    let backend = store.backend();
    let mut found: Option<os_entities::Identity> = None;
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Identity, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        found = Some(
            ciborium::from_reader(&v[..]).map_err(|e| ApiError::bad(format!("decode: {e}")))?,
        );
        break;
    }
    let id = found.ok_or_else(|| ApiError::not_found("no identity"))?;
    // We don't persist the previous-epoch private key, so for the test
    // surface we generate a fresh keypair each rotate (the chain
    // self-signs from a regenerated prev key for verification purposes).
    // Real implementation will wrap+persist priv keys under MK; tracked.
    let prev_priv_bytes = blake3::hash(format!("vault-mk-mock-priv-{}", id.identity_id.0).as_bytes());
    let prev_priv = os_types::Ed25519Priv(*prev_priv_bytes.as_bytes());
    let (new_epoch, _new_priv) = s
        .identity
        .rotate_identity(
            &id.identity_id,
            &prev_priv,
            os_types::Timestamp::from_string("now"),
        )
        .map_err(|e| ApiError::bad(format!("rotate: {e}")))?;
    Ok(Json(serde_json::json!({
        "new_epoch": new_epoch.epoch.0,
        "fingerprint": hex::encode(new_epoch.fingerprint.0),
    })))
}

async fn get_recovery(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let backend = s.vault.store().backend();
    let mut k = b"manifest:".to_vec();
    k.extend_from_slice(v.as_uuid().as_bytes());
    let bytes = backend
        .get(os_metadata::ColumnFamily::VaultMeta, &k)
        .map_err(|e| ApiError::bad(format!("read: {e}")))?
        .ok_or_else(|| ApiError::not_found("manifest"))?;
    let manifest: os_entities::RecoveryManifest = ciborium::from_reader(&bytes[..])
        .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
    let active_tokens: Vec<String> = manifest
        .recovery_token_active_set
        .live_values()
        .map(|t| t.to_string())
        .collect();
    Ok(Json(serde_json::json!({
        "manifest_id": manifest.manifest_id.to_string(),
        "version_counter": manifest.version_counter.0,
        "modes": manifest.modes.iter().map(|m| match m {
            os_entities::RecoveryMode::Passphrase => "passphrase",
            os_entities::RecoveryMode::RecoveryFile { .. } => "recovery_file",
            os_entities::RecoveryMode::Shamir { .. } => "shamir",
            os_entities::RecoveryMode::HardwareKey { .. } => "hardware_key",
        }).collect::<Vec<_>>(),
        "active_token_count": active_tokens.len(),
        "active_tokens": active_tokens,
        "identity_chain_length": manifest.identity_chain.len(),
    })))
}

async fn rotate_token_route(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let new_token = s
        .recovery
        .rotate_recovery_token(v)
        .map_err(|e| ApiError::bad(format!("rotate token: {e}")))?;
    Ok(Json(serde_json::json!({
        "new_token_id": new_token.to_string(),
    })))
}

async fn get_lease(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Json<serde_json::Value> {
    let state = match s.lease.state() {
        os_lease::LeaseState::Free => "free",
        os_lease::LeaseState::Held => "held",
    };
    Json(serde_json::json!({ "state": state }))
}

async fn acquire_lease(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = os_types::Timestamp::from_string("now");
    let expires = os_types::Timestamp::from_string("now+30s");
    let r = s
        .lease
        .acquire(s.device_id, now, expires)
        .map_err(|e| ApiError::bad(format!("lease: {e}")))?;
    Ok(Json(serde_json::json!({
        "lease_id": r.lease_id.to_string(),
        "holder_device_id": r.holder_device_id.to_string(),
        "renewal_count": r.renewal_count,
        "state": "held",
    })))
}

async fn renew_lease(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let r = s
        .lease
        .renew(os_types::Timestamp::from_string("now+30s"))
        .map_err(|e| ApiError::bad(format!("lease: {e}")))?;
    Ok(Json(serde_json::json!({
        "lease_id": r.lease_id.to_string(),
        "renewal_count": r.renewal_count,
        "state": "held",
    })))
}

async fn release_lease(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    s.lease
        .release()
        .map_err(|e| ApiError::bad(format!("lease: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_wal(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Json<serde_json::Value> {
    let wal = s.vfs.config(); // touch to keep import live in some configs
    let _ = wal;
    let next_seq = s
        .events
        .clone();
    let _ = next_seq;
    // We exposed wal next_seq via the SyncEngine inside VFS; expose via vault.
    let cur = s
        .vault
        .vault_id()
        .map(|v| v.to_string())
        .unwrap_or_default();
    Json(serde_json::json!({
        "vault_id": cur,
        "current_hlc": format!("{}", s.identity.store().backend().get(os_metadata::ColumnFamily::VaultMeta, b"_hlc").ok().flatten().map(|_| "n/a").unwrap_or("n/a")),
        "device_id": s.device_id.to_string(),
        "wal_path": "see engine logs",
    }))
}

async fn get_snapshot(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let vault = s
        .vault
        .store()
        .get_vault(v)
        .map_err(|e| ApiError::bad(format!("get_vault: {e}")))?
        .ok_or_else(|| ApiError::not_found("vault"))?;
    Ok(Json(serde_json::json!({
        "snapshot_id": hex::encode(&vault.snapshot_pointer.snapshot_id),
        "version_counter": vault.snapshot_pointer.version_counter.0,
        "epoch_id": vault.snapshot_pointer.epoch_id.0,
        "format_version": vault.snapshot_pointer.format_version,
    })))
}

async fn list_providers(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let providers = s
        .vault
        .store()
        .iter_providers()
        .map_err(|e| ApiError::bad(format!("iter: {e}")))?;
    let arr: Vec<_> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "provider_id": p.provider_id.to_string(),
                "plugin_id": p.plugin_id.0,
                "instance_label": p.instance_label,
                "trust_correlation_group": p.trust_correlation_group.0,
                "legal_class": format!("{:?}", p.legal_class),
                "health": p.health.value(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "providers": arr })))
}

async fn list_peers(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let backend = s.vault.store().backend();
    let mut peers = Vec::new();
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Peers, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let p: os_entities::Peer = ciborium::from_reader(&v[..])
            .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
        peers.push(serde_json::json!({
            "peer_id": p.peer_id.0,
            "label": p.label,
            "verified": p.verified,
            "epoch_count": p.epochs.len(),
            "last_seen_epoch": p.last_seen_epoch.0,
        }));
    }
    Ok(Json(serde_json::json!({ "peers": peers })))
}

async fn list_shadows(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let backend = s.vault.store().backend();
    let mut shadows = Vec::new();
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Shadows, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let sh: os_entities::Shadow = ciborium::from_reader(&v[..])
            .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
        shadows.push(serde_json::json!({
            "shadow_id": sh.shadow_id.to_string(),
            "original_chunk_hash": hex::encode(sh.original_chunk_hash.0),
            "driver_id": sh.driver_id.to_string(),
            "ciphertext_length": sh.ciphertext_length,
            "reason": format!("{:?}", sh.reason),
            "counts_against_quota": sh.counts_against_quota,
        }));
    }
    Ok(Json(serde_json::json!({ "shadows": shadows })))
}

async fn get_repair(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Json<serde_json::Value> {
    let st = s.repair.state();
    Json(serde_json::json!({
        "queue_depth": st.depth,
        "queue_max": st.max,
    }))
}

#[derive(Deserialize)]
struct EnqueueRepairReq {
    chunk_hash_hex: String,
    priority: Option<u32>,
    source: Option<String>,
}

async fn enqueue_repair(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
    Json(req): Json<EnqueueRepairReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bytes = hex::decode(&req.chunk_hash_hex).map_err(|_| ApiError::bad("bad hex"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad("chunk_hash must be 32 bytes hex"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    let source = match req.source.as_deref().unwrap_or("scrub") {
        "read_repair" => os_repair::RepairSource::ReadRepair,
        "scrub" => os_repair::RepairSource::Scrub,
        "anti_entropy" => os_repair::RepairSource::AntiEntropy,
        "gc_sweep" => os_repair::RepairSource::GcSweep,
        "rebalance" => os_repair::RepairSource::Rebalance,
        other => return Err(ApiError::bad(format!("unknown source {other}"))),
    };
    s.repair
        .enqueue(os_repair::RepairTask {
            chunk_hash: os_types::ChunkHash::from_bytes(h),
            priority: req.priority.unwrap_or(1),
            source,
            attempt: 0,
        })
        .map_err(|e| ApiError::bad(format!("enqueue: {e}")))?;
    let st = s.repair.state();
    Ok(Json(serde_json::json!({
        "queue_depth": st.depth,
    })))
}

async fn list_shares(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let backend = s.vault.store().backend();
    let mut shares = Vec::new();
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Shares, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let sh: os_entities::Share = ciborium::from_reader(&v[..])
            .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
        shares.push(serde_json::json!({
            "share_id": sh.share_id.to_string(),
            "recipient": sh.recipient.0,
            "scope": format!("{:?}", sh.scope),
            "revoked": sh.revoked_at.is_some(),
        }));
    }
    Ok(Json(serde_json::json!({ "shares": shares })))
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct CreateShareReq {
    /// PeerId string. We auto-create the peer if missing (test mode).
    recipient: String,
    /// Path scope, e.g., `/notes.txt` or `*` for vault-wide.
    scope: String,
}

async fn create_share(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
    Json(req): Json<CreateShareReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = if req.scope == "*" {
        os_entities::ShareScope::Vault
    } else if req.scope.ends_with('/') {
        os_entities::ShareScope::Folder(req.scope.clone())
    } else {
        os_entities::ShareScope::File(req.scope.clone())
    };
    let share = os_entities::Share {
        share_id: os_types::ShareId::new_v7(),
        scope,
        recipient: os_types::PeerId(req.recipient.clone()),
        permissions: vec![os_entities::Permission::Read],
        wrapped_keys_ref: os_entities::WrappedKeyRef {
            file_id: os_types::FileId::new_v7(),
            or_set_add_id: 0,
        },
        created_at: os_types::Timestamp::from_string("now"),
        expires_at: None,
        revoked_at: None,
    };
    let id = share.share_id;
    let mut txn = os_metadata::Txn::new();
    s.vault
        .store()
        .put_share(&mut txn, &share)
        .map_err(|e| ApiError::bad(format!("put_share: {e}")))?;
    s.vault
        .store()
        .commit(txn)
        .map_err(|e| ApiError::bad(format!("commit: {e}")))?;
    Ok(Json(serde_json::json!({ "share_id": id.to_string(), "state": "created" })))
}

async fn revoke_share(
    State(s): State<AppState>,
    Path((_vault_id, share_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let u = uuid::Uuid::parse_str(&share_id).map_err(|_| ApiError::bad("invalid share_id"))?;
    let id = os_types::ShareId::from_uuid(u);
    let mut share = s
        .vault
        .store()
        .get_share(id)
        .map_err(|e| ApiError::bad(format!("get_share: {e}")))?
        .ok_or_else(|| ApiError::not_found("share"))?;
    share.revoked_at = Some(os_types::Timestamp::from_string("now"));
    let mut txn = os_metadata::Txn::new();
    s.vault
        .store()
        .put_share(&mut txn, &share)
        .map_err(|e| ApiError::bad(format!("put_share: {e}")))?;
    s.vault
        .store()
        .commit(txn)
        .map_err(|e| ApiError::bad(format!("commit: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn push_snapshot_route(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let mut vault = s
        .vault
        .store()
        .get_vault(v)
        .map_err(|e| ApiError::bad(format!("get_vault: {e}")))?
        .ok_or_else(|| ApiError::not_found("vault"))?;

    let mk = s
        .vault
        .master_key()
        .ok_or_else(|| ApiError::bad("vault must be Unlocked"))?;

    // Walk every entity column family, CBOR-encode into a single blob,
    // AEAD-encrypt under the snapshot subkey, and push to the first
    // registered vault provider.
    let backend = s.vault.store().backend();
    let mut snapshot_payload: Vec<u8> = Vec::new();
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for cf in [
        os_metadata::ColumnFamily::Files,
        os_metadata::ColumnFamily::Chunks,
        os_metadata::ColumnFamily::Shards,
        os_metadata::ColumnFamily::Shadows,
        os_metadata::ColumnFamily::Providers,
        os_metadata::ColumnFamily::Identity,
        os_metadata::ColumnFamily::Peers,
        os_metadata::ColumnFamily::Shares,
        os_metadata::ColumnFamily::Devices,
    ] {
        for kv in backend
            .scan_prefix(cf, b"")
            .map_err(|e| ApiError::bad(format!("scan: {e}")))?
        {
            let (k, val) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
            entries.push((format!("{}/{}", cf.as_str(), hex::encode(k)), val));
        }
    }
    ciborium::into_writer(&entries, &mut snapshot_payload)
        .map_err(|e| ApiError::bad(format!("encode: {e}")))?;

    let snap_key = os_crypto::derive_subkey(&mk, os_types::KeyPurpose::SNAPSHOT, None)
        .map_err(|e| ApiError::bad(format!("derive: {e:?}")))?;
    let nonce = os_crypto::random_nonce_12();
    let aad = format!("snapshot:{}", v);
    let (ct, tag) = os_crypto::encrypt(
        os_types::AeadSuite::ChaCha20Poly1305,
        &snap_key,
        &nonce,
        &snapshot_payload,
        aad.as_bytes(),
    )
    .map_err(|e| ApiError::bad(format!("aead: {e:?}")))?;

    let nonce_bytes = match &nonce {
        os_types::AeadNonce::N12(b) => b.to_vec(),
        _ => return Err(ApiError::bad("nonce kind")),
    };
    let mut blob = Vec::with_capacity(12 + ct.len() + 16);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag.0);

    let etag = os_crypto::blake3_32(&blob);
    let snapshot_id = blob[..12].to_vec();

    // Push to the first registered vault provider.
    let vps = s.host.list_vault();
    let pushed_to: Option<String> = if let Some(provider_id) = vps.first() {
        let vp = s
            .host
            .get_vault(*provider_id)
            .map_err(|e| ApiError::bad(format!("get_vault_plugin: {e}")))?;
        let name = format!("snapshot/{}/v{}", v, vault.snapshot_pointer.version_counter.0 + 1);
        match vp.cas_write(&name, &blob, None).await {
            Ok(r) => match r.outcome {
                os_plugin_host::CasOutcome::Written => Some(name),
                _ => None,
            },
            Err(_) => None,
        }
    } else {
        None
    };

    vault.snapshot_pointer.version_counter =
        os_types::MonotonicCounter(vault.snapshot_pointer.version_counter.0 + 1);
    vault.snapshot_pointer.snapshot_id = snapshot_id.clone();
    vault.snapshot_pointer.created_at = os_types::Timestamp::from_string("now");
    let mut txn = os_metadata::Txn::new();
    s.vault
        .store()
        .put_vault(&mut txn, &vault)
        .map_err(|e| ApiError::bad(format!("put_vault: {e}")))?;
    s.vault
        .store()
        .commit(txn)
        .map_err(|e| ApiError::bad(format!("commit: {e}")))?;

    Ok(Json(serde_json::json!({
        "version_counter": vault.snapshot_pointer.version_counter.0,
        "snapshot_id": hex::encode(&snapshot_id),
        "etag": hex::encode(etag.as_bytes()),
        "blob_bytes": blob.len(),
        "entries": entries.len(),
        "pushed_to_vault_provider": pushed_to,
    })))
}

async fn get_fault(State(s): State<AppState>) -> Json<serde_json::Value> {
    if let Some(f) = &s.fault {
        return Json((f.snapshot)());
    }
    Json(serde_json::json!({"enabled": false}))
}

#[derive(Deserialize)]
struct FaultReq {
    fail_puts: Option<u32>,
    fail_gets: Option<u32>,
    corrupt_gets: Option<u32>,
    pause: Option<bool>,
}

async fn set_fault(
    State(s): State<AppState>,
    Json(req): Json<FaultReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let f = s.fault.as_ref().ok_or_else(|| ApiError::bad("fault injection disabled in this engine"))?;
    if let Some(n) = req.fail_puts {
        (f.fail_puts)(n);
    }
    if let Some(n) = req.fail_gets {
        (f.fail_gets)(n);
    }
    if let Some(n) = req.corrupt_gets {
        (f.corrupt_gets)(n);
    }
    if let Some(p) = req.pause {
        if p {
            (f.pause)();
        } else {
            (f.resume)();
        }
    }
    Ok(Json((f.snapshot)()))
}

async fn clear_fault(State(s): State<AppState>) -> Result<StatusCode, ApiError> {
    let f = s.fault.as_ref().ok_or_else(|| ApiError::bad("fault injection disabled"))?;
    (f.clear)();
    Ok(StatusCode::NO_CONTENT)
}

async fn get_provider_state(
    State(s): State<AppState>,
    Path((_vault_id, provider_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pid = parse_provider_id(&provider_id)?;
    let g = s.plugin_states.read().expect("plugin states");
    let state = g.get(&pid).copied().unwrap_or(PluginState::Loaded);
    Ok(Json(serde_json::json!({
        "provider_id": pid.to_string(),
        "state": state,
    })))
}

#[derive(Deserialize)]
struct ProviderStateReq {
    transition: String,
}

async fn set_provider_state(
    State(s): State<AppState>,
    Path((_vault_id, provider_id)): Path<(String, String)>,
    Json(req): Json<ProviderStateReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pid = parse_provider_id(&provider_id)?;
    let next = match req.transition.as_str() {
        "init" => PluginState::Init,
        "ready" => PluginState::Ready,
        "activate" => PluginState::Active,
        "pause" => PluginState::Paused,
        "resume" => PluginState::Active,
        "disable" => PluginState::Disabled,
        "close" => PluginState::Closed,
        other => return Err(ApiError::bad(format!("unknown transition {other}"))),
    };
    s.plugin_states
        .write()
        .expect("plugin states")
        .insert(pid, next);
    // Optionally pause/resume the underlying fault-injected plugin if attached.
    if let Some(f) = &s.fault {
        match next {
            PluginState::Paused | PluginState::Disabled => (f.pause)(),
            PluginState::Active | PluginState::Ready => (f.resume)(),
            _ => {}
        }
    }
    Ok(Json(serde_json::json!({"state": next})))
}

fn parse_provider_id(s: &str) -> Result<os_types::ProviderId, ApiError> {
    let u = uuid::Uuid::parse_str(s).map_err(|_| ApiError::bad("invalid provider_id"))?;
    Ok(os_types::ProviderId::from_uuid(u))
}

async fn events_tail(
    State(s): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Json<serde_json::Value> {
    // Drain a fresh subscription and return up to `limit` events. Since we
    // can't easily snapshot a ring buffer through the public API today, this
    // returns an empty list when `since` is None and queries the bus
    // internally — placeholder until the bus exposes a peek API.
    let _ = (s, q);
    Json(serde_json::json!({ "events": [] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use os_crypto::generate_keypair;
    use os_identity::IdentityService;
    use os_metadata::backend::MemoryBackend;
    use os_metadata::Store;
    use os_plugin_host::Host;
    use os_sync::SyncEngine;
    use os_types::DeviceId;
    use os_wal::WalBuilder;
    use rand::rngs::OsRng;
    use tower::ServiceExt;

    fn build_app() -> Router {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let identity = Arc::new(IdentityService::new(store.clone()));
        let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-api-test-{}", uuid::Uuid::now_v7()));
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
        let lease = Arc::new(os_lease::LeaseService::new());
        let repair = Arc::new(os_repair::RepairScheduler::new(1024));
        let events = Arc::new(os_events::EventBus::new());
        router(AppState {
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
        })
    }

    #[tokio::test]
    async fn create_then_write_and_read() {
        let app = build_app();
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/vaults")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"hunter2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(create_resp.into_body(), 8192)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let vault_id = parsed["vault_id"].as_str().unwrap().to_string();

        // PUT a file
        let put_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/notes.txt"))
                    .body(Body::from("hello via api"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK);

        // GET the file
        let get_resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/notes.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_resp.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"hello via api");
    }

    async fn create_vault_for_test(app: &Router) -> String {
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/vaults")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"hunter2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(create_resp.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        parsed["vault_id"].as_str().unwrap().to_string()
    }

    /// F-FL-5 — POST /files/{src}/move renames; src 404s; dst served.
    #[tokio::test]
    async fn move_file_via_api() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        // PUT a file
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/old.txt"))
                    .body(Body::from("contents"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // POST .../move
        let mv = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/files/old.txt/move"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"to":"/new.txt"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mv.status(), StatusCode::OK);
        // GET old → 404
        let old = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/old.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old.status(), StatusCode::NOT_FOUND);
        // GET new → 200 with contents
        let new = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/new.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(new.status(), StatusCode::OK);
        let body = axum::body::to_bytes(new.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"contents");
    }

    /// F-FL-5 — rename of nonexistent source returns 404.
    #[tokio::test]
    async fn move_missing_returns_404() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let mv = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/files/missing.txt/move"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"to":"/x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mv.status(), StatusCode::NOT_FOUND);
    }

    /// F-FL-3 — PATCH with Content-Range overwrites the named byte range.
    #[tokio::test]
    async fn patch_byte_range() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/data.bin"))
                    .body(Body::from(b"AAAAAAAAAAAA".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Patch bytes 4..=7 with "ZZZZ"
        let patch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/vaults/{vault_id}/files/data.bin"))
                    .header("content-range", "bytes 4-7/12")
                    .body(Body::from(b"ZZZZ".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch.status(), StatusCode::OK);
        let r = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/data.bin"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(r.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"AAAAZZZZAAAA");
    }

    /// F-FL-3 — PATCH with Content-Range that grows the file resizes it.
    #[tokio::test]
    async fn patch_grows_file() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/g.bin"))
                    .body(Body::from(b"hello".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let patch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/vaults/{vault_id}/files/g.bin"))
                    .header("content-range", "bytes 5-9/10")
                    .body(Body::from(b"WORLD".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch.status(), StatusCode::OK);
        let r = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/g.bin"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(r.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"helloWORLD");
    }

    /// F-FL-3 — PATCH on a missing file returns 404.
    #[tokio::test]
    async fn patch_missing_returns_404() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let r = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/vaults/{vault_id}/files/missing"))
                    .header("content-range", "bytes 0-2/3")
                    .body(Body::from(b"abc".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    /// F-FL-3 — PATCH without Content-Range header is rejected.
    #[tokio::test]
    async fn patch_without_content_range_400() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/x"))
                    .body(Body::from(b"hello".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let r = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/vaults/{vault_id}/files/x"))
                    .body(Body::from(b"X".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// F-FL-6 — HEAD returns size + file_id without a body.
    #[tokio::test]
    async fn head_returns_metadata_without_body() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/h.txt"))
                    .body(Body::from("12345"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let r = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/v1/vaults/{vault_id}/files/h.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get("x-size-bytes").unwrap().to_str().unwrap(),
            "5"
        );
        assert!(r.headers().get("x-file-id").is_some());
    }

    /// F-FL-4 — DELETE makes the file invisible to subsequent GETs (404).
    #[tokio::test]
    async fn delete_then_get_returns_404() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/d.txt"))
                    .body(Body::from("bye"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/vaults/{vault_id}/files/d.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::NO_CONTENT);
        let g = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/d.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(g.status(), StatusCode::NOT_FOUND);
    }

    /// F-VL-4 — DELETE /v1/vaults/{v} requires the confirm header and
    /// transitions the vault to Destroyed.
    #[tokio::test]
    async fn destroy_vault_via_api() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        // Without header → 400.
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/vaults/{vault_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        // With header → 200.
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/vaults/{vault_id}"))
                    .header("x-confirm-destroy", "yes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let st = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/system/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(st.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["state"], "destroyed");
    }

    /// F-VL-5 — POST /rotate-mk swaps the unlock secret.
    #[tokio::test]
    async fn rotate_mk_via_api() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/rotate-mk"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"new_passphrase":"new"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        // Lock then unlock with new pass.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lock"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let unlock = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/unlock"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"new"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock.status(), StatusCode::NO_CONTENT);
        // Old passphrase rejected.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lock"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bad = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/unlock"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"hunter2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    }

    /// 6.A.4 — POST /recovery/rotate-token returns a new token id and the
    /// active-set count stays at 1 (the new id replaces the old).
    #[tokio::test]
    async fn rotate_recovery_token_via_api() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/recovery/rotate-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["new_token_id"].as_str().is_some());

        let g = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/recovery"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(g.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["active_token_count"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn lock_then_read_returns_423() {
        let app = build_app();
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/vaults")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Look up vault_id via /v1/system/status
        let st = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/system/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(st.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let vault_id = parsed["vault_id"].as_str().unwrap().to_string();
        // PUT a file
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/x"))
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Lock
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lock"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Read should return 423
        let r = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/x"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 423);
    }
}
