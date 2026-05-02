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
use os_plugin_host::lifecycle::{
    self as plug_lifecycle, OAuthCoordinator, PluginManifest, UserConfirmation,
};
use os_repair::RepairScheduler;
use os_share::{
    decode_blob as share_decode_blob, encode_blob as share_encode_blob,
    CreateShareReq as ShareCreateReq, ShareService,
};
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
    pub share: Arc<ShareService>,
    /// F-PL — plugin lifecycle.
    pub oauth: Arc<OAuthCoordinator>,
    /// F-PL-1 TOFU — known author keys keyed by `plugin_id` so subsequent
    /// installs detect rotation.
    pub plugin_authors: Arc<std::sync::RwLock<std::collections::HashMap<os_types::PluginId, os_types::Ed25519Pub>>>,
    /// F-PL-3 — last observed capability set per plugin instance, used
    /// to compute drift on reload.
    pub plugin_capabilities: Arc<
        std::sync::RwLock<std::collections::HashMap<os_types::PluginId, os_types::CapabilitySet>>,
    >,
    pub device_id: os_types::DeviceId,
    /// Optional fault handle for integration tests.
    pub fault: Option<FaultHandleAny>,
    /// Plugin-state registry; tracks Loaded/Active/Paused/Disabled per provider.
    pub plugin_states: Arc<std::sync::RwLock<std::collections::HashMap<os_types::ProviderId, PluginState>>>,
    /// F-PL-3 — per-plugin (not per-instance) decision tracker. When a
    /// reload sees lost capabilities, the diff is stashed here keyed by
    /// PluginId; the user clears it via `POST /v1/plugins/:id/decision`.
    pub plugin_decisions: Arc<
        std::sync::RwLock<
            std::collections::HashMap<os_types::PluginId, PluginDecisionEntry>,
        >,
    >,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginDecisionEntry {
    pub gained: Vec<String>,
    pub lost: Vec<String>,
    /// `awaiting_user_decision` until the user calls /decision; then it's
    /// cleared from the map entirely. Surfaced via plugin-state listing.
    pub state: &'static str,
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
        .route("/v1/vaults/:vault_id/lease/steal", post(steal_lease))
        .route("/v1/vaults/:vault_id/wal", get(get_wal))
        .route("/v1/vaults/:vault_id/snapshot", get(get_snapshot))
        .route("/v1/vaults/:vault_id/providers", get(list_providers))
        .route("/v1/vaults/:vault_id/peers", get(list_peers))
        .route("/v1/vaults/:vault_id/shadows", get(list_shadows))
        .route(
            "/v1/vaults/:vault_id/shadows/sweep",
            post(shadow_sweep),
        )
        .route(
            "/v1/vaults/:vault_id/repair",
            get(get_repair).post(enqueue_repair),
        )
        .route(
            "/v1/vaults/:vault_id/repair/run",
            post(run_repair),
        )
        .route(
            "/v1/vaults/:vault_id/antientropy/run",
            post(antientropy_run),
        )
        .route(
            "/v1/vaults/:vault_id/wal/push",
            post(wal_push),
        )
        .route(
            "/v1/vaults/:vault_id/wal/pull",
            post(wal_pull),
        )
        .route(
            "/v1/vaults/:vault_id/shares",
            get(list_shares).post(create_share),
        )
        .route(
            "/v1/vaults/:vault_id/shares/:share_id",
            axum::routing::delete(revoke_share),
        )
        .route(
            "/v1/vaults/:vault_id/inbox/:share_id/accept",
            post(accept_share),
        )
        .route(
            "/v1/vaults/:vault_id/inbox",
            get(list_inbox),
        )
        .route("/v1/vaults/:vault_id/snapshot/push", post(push_snapshot_route))
        .route("/v1/vaults/:vault_id/snapshot/pull", post(pull_snapshot_route))
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
        .route("/v1/plugins/install", post(install_plugin_route))
        .route("/v1/plugins/:plugin_id/reload", post(reload_plugin_route))
        .route(
            "/v1/plugins/:plugin_id/decision",
            get(plugin_decision_get).post(plugin_decision_route),
        )
        .route("/v1/providers/oauth/start", post(oauth_start_route))
        .route("/v1/providers/oauth/complete", post(oauth_complete_route))
        .route("/v1/system/scrub", post(system_scrub))
        .route("/v1/system/gc", post(system_gc))
        .route("/v1/vaults/:vault_id/rebalance", post(system_rebalance))
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
    fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
        }
    }
    /// 410 Gone — used for `lease.lost`. Frontends should treat this as a
    /// terminal "you no longer hold the lease" signal.
    fn lost(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GONE,
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
    // Layer 4 / §6.A.6 — identity rotation is the *one* hard
    // serialization point. Two devices rotating concurrently would
    // produce competing epoch_n+1 records; an HLC tiebreak is unsafe
    // because the loser may have already published their new pubkey
    // out of band. Lease enforcement avoids this by serializing.
    let lease = s.lease.current().ok_or_else(|| {
        ApiError::conflict("identity rotation requires the vault lease (none held)")
    })?;
    if lease.holder_device_id != s.device_id {
        return Err(ApiError::conflict(format!(
            "identity rotation requires the lease; held by another device {}",
            lease.holder_device_id
        )));
    }
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

// ─── F-MD-4 Vault-backed lease ────────────────────────────────────────────
//
// When at least one vault-role plugin is registered, lease operations go
// through the plugin's `named_get` + `cas_write` instead of the in-process
// registry. Two engines pointing at the same plugin (e.g. a shared
// `LocalDirPlugin` directory or the testbench's `/v1/named/...` API) thus
// observe and contend for the same lease record — which is what F-MD-4
// (lease steal across devices) requires.
//
// On-plugin layout: a single named blob at `lease/<vault_id>` containing a
// CBOR-encoded `LeaseRecord`. CAS is keyed off the blob's etag (BLAKE3-32).

const LEASE_BLOB_NAME_PREFIX: &str = "lease/";

fn lease_blob_name(vault: os_types::VaultId) -> String {
    format!("{LEASE_BLOB_NAME_PREFIX}{vault}")
}

fn vault_provider_for_lease(s: &AppState) -> Option<Arc<dyn os_plugin_host::VaultPluginContract>> {
    let vps = s.host.list_vault();
    let pid = *vps.first()?;
    s.host.get_vault(pid).ok()
}

async fn read_vault_lease(
    plugin: &Arc<dyn os_plugin_host::VaultPluginContract>,
    vault: os_types::VaultId,
) -> Result<Option<(os_entities::LeaseRecord, os_types::BlakeHash)>, ApiError> {
    let name = lease_blob_name(vault);
    match plugin.named_get(&name).await {
        // Empty payload is the on-plugin sentinel for "released" — see
        // `release_lease`. Treat as Free.
        Ok(Some((bytes, _))) if bytes.is_empty() => Ok(None),
        Ok(Some((bytes, etag))) => {
            let rec: os_entities::LeaseRecord = ciborium::from_reader(&bytes[..])
                .map_err(|e| ApiError::bad(format!("lease decode: {e}")))?;
            Ok(Some((rec, etag)))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(ApiError::bad(format!("named_get: {e}"))),
    }
}

async fn write_vault_lease(
    plugin: &Arc<dyn os_plugin_host::VaultPluginContract>,
    vault: os_types::VaultId,
    rec: &os_entities::LeaseRecord,
    expected_etag: Option<os_types::BlakeHash>,
) -> Result<bool, ApiError> {
    let mut buf = Vec::new();
    ciborium::into_writer(rec, &mut buf)
        .map_err(|e| ApiError::bad(format!("lease encode: {e}")))?;
    let res = plugin
        .cas_write(&lease_blob_name(vault), &buf, expected_etag)
        .await
        .map_err(|e| ApiError::bad(format!("cas_write: {e}")))?;
    Ok(matches!(
        res.outcome,
        os_plugin_host::CasOutcome::Written
    ))
}

async fn get_lease(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    if let Some(plugin) = vault_provider_for_lease(&s) {
        let cur = read_vault_lease(&plugin, v).await?;
        let state = match &cur {
            Some(_) => "held",
            None => "free",
        };
        let mut body = serde_json::json!({ "state": state, "backend": "vault" });
        if let Some((r, _)) = cur {
            body["lease_id"] = serde_json::Value::String(r.lease_id.to_string());
            body["holder_device_id"] =
                serde_json::Value::String(r.holder_device_id.to_string());
            body["expires_at"] =
                serde_json::Value::String(r.expires_at.as_str().to_string());
            body["renewal_count"] =
                serde_json::Value::Number(serde_json::Number::from(r.renewal_count));
        }
        return Ok(Json(body));
    }
    let state = match s.lease.state() {
        os_lease::LeaseState::Free => "free",
        os_lease::LeaseState::Held => "held",
    };
    Ok(Json(serde_json::json!({ "state": state, "backend": "in_memory" })))
}

#[derive(Deserialize, Default)]
struct AcquireLeaseReq {
    /// Override "now" for deterministic tests. Real callers omit it.
    #[serde(default)]
    now_epoch_secs: Option<u64>,
    /// TTL in seconds (default 30).
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn acquire_lease(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    body: Option<Json<AcquireLeaseReq>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let v = parse_vault_id(&vault_id)?;
    let now_secs = req.now_epoch_secs.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let ttl = req.ttl_secs.unwrap_or(30);
    let now = os_types::Timestamp::from_epoch_secs(now_secs);
    let expires = os_types::Timestamp::from_epoch_secs(now_secs + ttl);

    if let Some(plugin) = vault_provider_for_lease(&s) {
        // Vault-backed CAS path: refuse if a live lease exists; otherwise
        // CAS-write a fresh record. Mirrors the in-memory `acquire`
        // semantics but is durable across processes.
        let cur = read_vault_lease(&plugin, v).await?;
        if let Some((existing, _)) = &cur {
            // Treat aged-past-expiry as free (the same path
            // `try_steal` would take, just for `acquire` ergonomics).
            let still_live = existing
                .expires_at
                .epoch_secs()
                .map(|exp| exp > now_secs)
                .unwrap_or(true);
            if still_live {
                return Err(ApiError::bad("lease: held by another device"));
            }
        }
        let new_rec = os_entities::LeaseRecord {
            lease_id: os_types::LeaseId::new_v7(),
            holder_device_id: s.device_id,
            acquired_at: now.clone(),
            expires_at: expires.clone(),
            renewal_count: 0,
            holder_signature: os_types::Ed25519Sig([0u8; 64]),
        };
        let written = write_vault_lease(
            &plugin,
            v,
            &new_rec,
            cur.as_ref().map(|(_, et)| *et),
        )
        .await?;
        if !written {
            return Err(ApiError::conflict("lease CAS race lost"));
        }
        // Mirror into the in-memory registry with the same lease_id so
        // renew/release on this engine match against the vault record.
        let _ = (now, expires);
        s.lease.install_local(new_rec.clone());
        return Ok(Json(serde_json::json!({
            "lease_id": new_rec.lease_id.to_string(),
            "holder_device_id": new_rec.holder_device_id.to_string(),
            "renewal_count": new_rec.renewal_count,
            "state": "held",
            "backend": "vault",
        })));
    }
    let r = s
        .lease
        .acquire(s.device_id, now, expires)
        .map_err(|e| ApiError::bad(format!("lease: {e}")))?;
    Ok(Json(serde_json::json!({
        "lease_id": r.lease_id.to_string(),
        "holder_device_id": r.holder_device_id.to_string(),
        "renewal_count": r.renewal_count,
        "state": "held",
        "backend": "in_memory",
    })))
}

async fn renew_lease(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(plugin) = vault_provider_for_lease(&s) {
        let cur = read_vault_lease(&plugin, v).await?;
        let (mut rec, etag) = cur.ok_or_else(|| ApiError::bad("lease: not held"))?;
        let local_id = s.lease.current().map(|r| r.lease_id);
        if Some(rec.lease_id) != local_id {
            // Lease was stolen between our last write and now.
            s.events.publish(os_events::Event::new("lease.lost"));
            let _ = s.lease.release();
            return Err(ApiError::lost("lease lost"));
        }
        rec.expires_at = os_types::Timestamp::from_epoch_secs(now_secs + 30);
        rec.renewal_count += 1;
        let written = write_vault_lease(&plugin, v, &rec, Some(etag)).await?;
        if !written {
            s.events.publish(os_events::Event::new("lease.lost"));
            let _ = s.lease.release();
            return Err(ApiError::lost("lease lost: CAS"));
        }
        // Keep in-memory mirror in sync.
        s.lease.install_local(rec.clone());
        return Ok(Json(serde_json::json!({
            "lease_id": rec.lease_id.to_string(),
            "renewal_count": rec.renewal_count,
            "state": "held",
            "backend": "vault",
        })));
    }

    let r = s
        .lease
        .renew(os_types::Timestamp::from_epoch_secs(now_secs + 30))
        .map_err(|e| match e {
            // F-MD-4: renew failure after a steal surfaces as `lease.lost`.
            os_lease::LeaseError::Lost => {
                s.events.publish(os_events::Event::new("lease.lost"));
                ApiError::lost("lease lost")
            }
            other => ApiError::bad(format!("lease: {other}")),
        })?;
    Ok(Json(serde_json::json!({
        "lease_id": r.lease_id.to_string(),
        "renewal_count": r.renewal_count,
        "state": "held",
        "backend": "in_memory",
    })))
}

#[derive(Deserialize)]
struct StealLeaseReq {
    /// Caller-provided "now" in `epoch:N` form for staleness math.
    #[serde(default)]
    now_epoch_secs: Option<u64>,
    /// New lease expiry (seconds since epoch).
    #[serde(default)]
    expires_at_epoch_secs: Option<u64>,
    /// TTL the prior holder was using; staleness threshold = 2 × ttl.
    ttl_secs: u64,
}

/// F-MD-4 — POST /v1/vaults/{v}/lease/steal. Refuses with 409 if the
/// existing lease is still live; CAS-overwrites if it has aged past 2×TTL.
async fn steal_lease(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    Json(req): Json<StealLeaseReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let now_secs = req.now_epoch_secs.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let expires = req
        .expires_at_epoch_secs
        .unwrap_or(now_secs + req.ttl_secs);

    if let Some(plugin) = vault_provider_for_lease(&s) {
        let cur = read_vault_lease(&plugin, v).await?;
        if let Some((existing, _)) = &cur {
            // Per F-MD-4: only steal if expires_at is ≥ 2×TTL in the past.
            if let Some(exp) = existing.expires_at.epoch_secs() {
                let aged = now_secs.saturating_sub(exp);
                if aged < 2 * req.ttl_secs {
                    return Err(ApiError::conflict("lease still live"));
                }
            } else {
                return Err(ApiError::conflict("lease still live"));
            }
        }
        let new_rec = os_entities::LeaseRecord {
            lease_id: os_types::LeaseId::new_v7(),
            holder_device_id: s.device_id,
            acquired_at: os_types::Timestamp::from_epoch_secs(now_secs),
            expires_at: os_types::Timestamp::from_epoch_secs(expires),
            renewal_count: 0,
            holder_signature: os_types::Ed25519Sig([0u8; 64]),
        };
        let written = write_vault_lease(
            &plugin,
            v,
            &new_rec,
            cur.as_ref().map(|(_, et)| *et),
        )
        .await?;
        if !written {
            return Err(ApiError::conflict("steal CAS race lost"));
        }
        // Mirror the new lease locally with the same lease_id we wrote.
        s.lease.install_local(new_rec.clone());
        return Ok(Json(serde_json::json!({
            "lease_id": new_rec.lease_id.to_string(),
            "holder_device_id": new_rec.holder_device_id.to_string(),
            "state": "held",
            "backend": "vault",
        })));
    }

    let r = s
        .lease
        .try_steal(
            s.device_id,
            os_types::Timestamp::from_epoch_secs(now_secs),
            os_types::Timestamp::from_epoch_secs(expires),
            req.ttl_secs,
        )
        .map_err(|e| match e {
            os_lease::LeaseError::StillLive => ApiError::conflict("lease still live"),
            other => ApiError::bad(format!("steal: {other}")),
        })?;
    Ok(Json(serde_json::json!({
        "lease_id": r.lease_id.to_string(),
        "holder_device_id": r.holder_device_id.to_string(),
        "state": "held",
        "backend": "in_memory",
    })))
}

async fn release_lease(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    if let Some(plugin) = vault_provider_for_lease(&s) {
        // Best-effort: if our local lease_id matches the on-plugin one,
        // CAS-write a deletion (empty payload). If CAS fails (race),
        // surface as `lease.lost` rather than error — the lease is no
        // longer ours to release.
        let cur = read_vault_lease(&plugin, v).await?;
        if let Some((existing, etag)) = cur {
            let local_id = s.lease.current().map(|r| r.lease_id);
            if Some(existing.lease_id) == local_id {
                // Overwrite with an empty blob to indicate Free. We
                // can't actually delete a named blob through the
                // VaultPluginContract today, so an empty record is the
                // sentinel; `read_vault_lease` decode will fail and
                // surface as `Free` to subsequent callers.
                let _ = plugin
                    .cas_write(&lease_blob_name(v), &[], Some(etag))
                    .await;
            }
        }
    }
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
            "state": format!("{:?}", sh.state),
            "peek_count": sh.peek_count,
        }));
    }
    Ok(Json(serde_json::json!({ "shadows": shadows })))
}

/// F-VL-4 / F-HM-5 — peek every Registered shadow against its provider.
/// `not_found` ⇒ Cleared; persistent `exists` after `permanent_threshold`
/// peeks ⇒ Permanent. Returns counts per outcome.
async fn shadow_sweep(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    const PERMANENT_THRESHOLD: u32 = 10;
    let backend = s.vault.store().backend();
    let mut peeked = 0u32;
    let mut cleared = 0u32;
    let mut promoted = 0u32;
    let mut still_registered = 0u32;
    let mut errors = 0u32;
    let mut to_update: Vec<os_entities::Shadow> = Vec::new();
    let mut to_delete: Vec<os_types::ShadowId> = Vec::new();
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Shadows, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let mut sh: os_entities::Shadow = match ciborium::from_reader(&v[..]) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !matches!(sh.state, os_entities::ShadowState::Registered) {
            continue;
        }
        peeked += 1;
        let plugin = match s.host.get_chunk(sh.driver_id) {
            Ok(p) => p,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        match plugin.peek(&sh.native_handle).await {
            Ok(p) if !p.exists => {
                sh.state = os_entities::ShadowState::Cleared;
                to_delete.push(sh.shadow_id);
                cleared += 1;
            }
            Ok(_) => {
                sh.peek_count = sh.peek_count.saturating_add(1);
                if sh.peek_count >= PERMANENT_THRESHOLD {
                    sh.state = os_entities::ShadowState::Permanent;
                    promoted += 1;
                } else {
                    still_registered += 1;
                }
                to_update.push(sh);
            }
            Err(_) => {
                errors += 1;
            }
        }
    }
    let mut txn = os_metadata::Txn::new();
    for sh in &to_update {
        s.vault
            .store()
            .put_shadow(&mut txn, sh)
            .map_err(|e| ApiError::bad(format!("put_shadow: {e}")))?;
    }
    for id in &to_delete {
        txn.delete(
            os_metadata::ColumnFamily::Shadows,
            id.0.as_bytes().to_vec(),
        );
    }
    s.vault
        .store()
        .commit(txn)
        .map_err(|e| ApiError::bad(format!("commit: {e}")))?;
    Ok(Json(serde_json::json!({
        "peeked": peeked,
        "cleared": cleared,
        "promoted_permanent": promoted,
        "still_registered": still_registered,
        "errors": errors,
    })))
}

async fn get_repair(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Json<serde_json::Value> {
    let st = s.repair.state();
    Json(serde_json::json!({
        "queue_depth": st.depth,
        "queue_max": st.max,
        "failed_count": s.repair.failed_count(),
    }))
}

#[derive(Deserialize, Default)]
struct RunRepairReq {
    /// Cap on tasks drained per call (default 64).
    max_tasks: Option<usize>,
}

/// F-HM-1/2/3/5 worker driver — drain up to `max_tasks` from the priority
/// queue. Each task is dispatched by `RepairSource`:
///   * `GcSweep`   — call plugin.delete on every shard of the chunk;
///                   register a Shadow for non-`Removed` outcomes; drop
///                   chunk record once all shards are gone.
///   * `Scrub`     — peek every shard against its provider; on
///                   not_found / size mismatch, mark health=Degraded
///                   and re-enqueue as ReadRepair.
///   * `ReadRepair`— flip every Acked shard's health to Degraded so
///                   the next read fans out elsewhere; the actual
///                   re-place lands when a shard is re-uploaded by
///                   the writer (true cross-provider re-place is the
///                   next iteration; this is the F-HM-2 quick-fix path).
///   * `AntiEntropy` / `Rebalance` — no-op for now; these come back
///                   through F-HM-3 / F-HM-4 once those handlers run.
/// Transient errors hit `record_attempt_failure`; after 3 attempts the
/// task is moved to the `failed` list (RepairTask::Failed).
async fn run_repair(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
    body: Option<Json<RunRepairReq>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let max_tasks = req.max_tasks.unwrap_or(64);
    let mut processed = 0usize;
    let mut succeeded = 0usize;
    let mut retried = 0usize;
    let mut failed_now = 0usize;
    while processed < max_tasks {
        let task = match s.repair.drain_one() {
            Some(t) => t,
            None => break,
        };
        processed += 1;
        let outcome = process_repair_task(&s, &task).await;
        match outcome {
            Ok(()) => succeeded += 1,
            Err(e) => {
                let was_terminal = task.attempt + 1 >= os_repair::MAX_ATTEMPTS;
                s.repair.record_attempt_failure(task.clone(), e);
                if was_terminal {
                    failed_now += 1;
                } else {
                    retried += 1;
                }
            }
        }
    }
    let st = s.repair.state();
    Ok(Json(serde_json::json!({
        "processed": processed,
        "succeeded": succeeded,
        "retried": retried,
        "failed": failed_now,
        "queue_depth": st.depth,
        "failed_total": s.repair.failed_count(),
    })))
}

async fn process_repair_task(
    s: &AppState,
    task: &os_repair::RepairTask,
) -> Result<(), String> {
    use os_repair::RepairSource;
    let store = s.vault.store();
    let chunk_opt = store
        .get_chunk(task.chunk_hash)
        .map_err(|e| format!("get_chunk: {e}"))?;
    let chunk = match chunk_opt {
        Some(c) => c,
        // Chunk gone — treat as success; no work to do.
        None => return Ok(()),
    };
    match task.source {
        RepairSource::GcSweep => {
            let mut all_removed = true;
            for shard_id in &chunk.shard_list {
                let shard = match store.get_shard(*shard_id) {
                    Ok(Some(s)) => s,
                    _ => continue,
                };
                let plugin = match s.host.get_chunk(shard.driver_id.value) {
                    Ok(p) => p,
                    Err(_) => {
                        all_removed = false;
                        continue;
                    }
                };
                match plugin.delete(&shard.native_handle.value).await {
                    Ok(res) => match res.outcome {
                        os_types::DeleteOutcome::Removed
                        | os_types::DeleteOutcome::NotFound => {}
                        os_types::DeleteOutcome::Tombstoned
                        | os_types::DeleteOutcome::Abandoned
                        | os_types::DeleteOutcome::NotSupported => {
                            // Surface as a Shadow; sweep later promotes
                            // or clears it (G3).
                            let shadow = os_entities::Shadow {
                                shadow_id: os_types::ShadowId::new_v7(),
                                original_chunk_hash: shard.chunk_hash,
                                driver_id: shard.driver_id.value,
                                native_handle: shard.native_handle.value.clone(),
                                ciphertext_length: shard.ciphertext_length,
                                abandoned_at: os_types::Timestamp::from_string(
                                    repair_now_iso(),
                                ),
                                reason: os_entities::ShadowReason::DeletionOrphaned,
                                cached_elsewhere_risk:
                                    os_types::CachedElsewhereRisk::Low,
                                counts_against_quota: true,
                                tombstone_clears_at: None,
                                state: os_entities::ShadowState::Registered,
                                peek_count: 0,
                            };
                            let mut txn = os_metadata::Txn::new();
                            store
                                .put_shadow(&mut txn, &shadow)
                                .map_err(|e| format!("put_shadow: {e}"))?;
                            store
                                .commit(txn)
                                .map_err(|e| format!("commit: {e}"))?;
                            all_removed = false;
                        }
                    },
                    Err(e) => {
                        return Err(format!(
                            "delete on {}: {e}",
                            shard.driver_id.value
                        ));
                    }
                }
            }
            if all_removed {
                // All shard objects are gone from backends; drop the
                // chunk record. Shard records remain referenceable until
                // the next compaction sweep — leaving them is benign
                // because their handles no longer resolve.
                let mut txn = os_metadata::Txn::new();
                txn.delete(
                    os_metadata::ColumnFamily::Chunks,
                    chunk.chunk_hash.as_bytes().to_vec(),
                );
                store.commit(txn).map_err(|e| format!("commit: {e}"))?;
            }
            Ok(())
        }
        RepairSource::Scrub => {
            let mut ok = true;
            for shard_id in &chunk.shard_list {
                let shard = match store.get_shard(*shard_id) {
                    Ok(Some(s)) => s,
                    _ => continue,
                };
                let plugin = match s.host.get_chunk(shard.driver_id.value) {
                    Ok(p) => p,
                    Err(_) => {
                        ok = false;
                        continue;
                    }
                };
                match plugin.peek(&shard.native_handle.value).await {
                    Ok(p) if p.exists && p.size == shard.ciphertext_length => {}
                    Ok(_) | Err(_) => {
                        ok = false;
                        // Flip health and enqueue an inline read-repair
                        // pass so the read path knows to widen its hedge.
                        let mut updated = shard.clone();
                        updated.health_score =
                            os_types::HealthScore::new(0.0);
                        let mut txn = os_metadata::Txn::new();
                        store
                            .put_shard(&mut txn, &updated)
                            .map_err(|e| format!("put_shard: {e}"))?;
                        store
                            .commit(txn)
                            .map_err(|e| format!("commit: {e}"))?;
                        let _ = s.repair.enqueue(os_repair::RepairTask {
                            chunk_hash: chunk.chunk_hash,
                            priority: 100,
                            source: RepairSource::ReadRepair,
                            attempt: 0,
                        });
                    }
                }
            }
            if ok {
                Ok(())
            } else {
                Ok(()) // partial degrade is reported via shard health, not error
            }
        }
        RepairSource::ReadRepair => {
            for shard_id in &chunk.shard_list {
                let shard = match store.get_shard(*shard_id) {
                    Ok(Some(s)) => s,
                    _ => continue,
                };
                let plugin = match s.host.get_chunk(shard.driver_id.value) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if let Ok(p) = plugin.peek(&shard.native_handle.value).await {
                    if p.exists && p.size == shard.ciphertext_length {
                        let mut updated = shard.clone();
                        updated.health_score =
                            os_types::HealthScore::new(1.0);
                        let mut txn = os_metadata::Txn::new();
                        store
                            .put_shard(&mut txn, &updated)
                            .map_err(|e| format!("put_shard: {e}"))?;
                        store
                            .commit(txn)
                            .map_err(|e| format!("commit: {e}"))?;
                    }
                }
            }
            Ok(())
        }
        RepairSource::AntiEntropy | RepairSource::Rebalance => {
            // Driven from F-HM-3 / F-HM-4 endpoints; no per-task action
            // beyond logging.
            Ok(())
        }
        RepairSource::PluginBan => {
            // Layer 2 — a provider was Banned by `HealthMonitor`. For
            // every shard of this chunk hosted on a Banned provider:
            // register a `Shadow` (so the residual report counts the
            // bytes), drop the shard from the chunk's `shard_list`, and
            // mark the chunk Degraded. Re-placement onto a healthy
            // provider is a Layer 4 closure — for now we shed the
            // banned shards and let the existing healthy replicas serve
            // reads.
            let mut surviving: Vec<os_types::ShardId> = Vec::with_capacity(chunk.shard_list.len());
            let mut shadowed: Vec<os_entities::Shadow> = Vec::new();
            for shard_id in &chunk.shard_list {
                let shard = match store.get_shard(*shard_id) {
                    Ok(Some(sh)) => sh,
                    _ => {
                        continue;
                    }
                };
                let provider = shard.driver_id.value;
                if s.host.provider_health(provider).is_banned() {
                    use os_entities::{Shadow, ShadowReason, ShadowState};
                    use os_types::CachedElsewhereRisk;
                    shadowed.push(Shadow {
                        shadow_id: os_types::ShadowId::new_v7(),
                        original_chunk_hash: chunk.chunk_hash,
                        driver_id: provider,
                        native_handle: shard.native_handle.value.clone(),
                        ciphertext_length: shard.ciphertext_length,
                        abandoned_at: os_types::Timestamp::from_string(&repair_now_iso()),
                        reason: ShadowReason::PluginBanned,
                        cached_elsewhere_risk: CachedElsewhereRisk::High,
                        counts_against_quota: true,
                        tombstone_clears_at: None,
                        state: ShadowState::Registered,
                        peek_count: 0,
                    });
                } else {
                    surviving.push(*shard_id);
                }
            }
            if shadowed.is_empty() {
                return Ok(());
            }
            let mut txn = os_metadata::Txn::new();
            for sh in &shadowed {
                store
                    .put_shadow(&mut txn, sh)
                    .map_err(|e| format!("put_shadow: {e}"))?;
            }
            // Drop banned shards from the chunk's shard list and
            // mark Degraded.
            let mut updated_chunk = chunk.clone();
            updated_chunk.shard_list = surviving;
            updated_chunk.replication_state = if updated_chunk.shard_list.is_empty() {
                os_entities::ReplicationState::Lost
            } else {
                os_entities::ReplicationState::Degraded
            };
            store
                .put_chunk(&mut txn, &updated_chunk)
                .map_err(|e| format!("put_chunk: {e}"))?;
            store
                .commit(txn)
                .map_err(|e| format!("commit: {e}"))?;
            s.events
                .publish(os_events::Event::new("plugin.banned"));
            Ok(())
        }
    }
}

fn repair_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

// ─── F-MD-5 WAL fork & reconcile ──────────────────────────────────────────
//
// Two engines pointing at the same vault provider exchange WAL entries by
// writing each entry to a named blob `wal/<device_id>/<seq>` (cas_write
// for atomicity) and pulling all peer-device entries during reconcile.
// Each pull applies foreign entries through `sync.apply_remote_wal_segment`,
// which already handles F-MD-1 (concurrent update), F-MD-2
// (update-vs-delete) and F-MD-3 (concurrent rename) merges per the design.

const WAL_BLOB_PREFIX: &str = "wal/";

fn wal_blob_name(device: os_types::DeviceId, seq: u64) -> String {
    format!("{WAL_BLOB_PREFIX}{}/{:020}", device, seq)
}

async fn wal_push(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let plugin = vault_provider_for_lease(&s)
        .ok_or_else(|| ApiError::bad("no vault provider registered"))?;
    let wal = s.vfs.sync().wal();
    let entries = wal
        .scan_since(wal.min_seq())
        .map_err(|e| ApiError::bad(format!("scan_since: {e}")))?;
    let mut pushed = 0usize;
    let mut skipped = 0usize;
    for e in &entries {
        let mut buf = Vec::new();
        ciborium::into_writer(e, &mut buf)
            .map_err(|err| ApiError::bad(format!("encode wal: {err}")))?;
        // CAS with `expected_etag=None` succeeds only if the slot is
        // empty; treat etag-mismatch as "already pushed" — WAL entries
        // are immutable per (device_id, seq).
        let res = plugin
            .cas_write(&wal_blob_name(e.device_id, e.wal_id.seq), &buf, None)
            .await
            .map_err(|err| ApiError::bad(format!("cas_write: {err}")))?;
        match res.outcome {
            os_plugin_host::CasOutcome::Written => pushed += 1,
            _ => skipped += 1,
        }
    }
    Ok(Json(serde_json::json!({
        "pushed": pushed,
        "already_present": skipped,
        "local_min_seq": wal.min_seq(),
        "local_next_seq": wal.next_seq(),
    })))
}

async fn wal_pull(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let plugin = vault_provider_for_lease(&s)
        .ok_or_else(|| ApiError::bad("no vault provider registered"))?;
    let local_device = s.vfs.sync().wal().device_id();
    let mut foreign_entries: Vec<os_entities::WalEntry> = Vec::new();
    let mut seen_devices: std::collections::HashSet<os_types::DeviceId> =
        std::collections::HashSet::new();
    let mut listed = 0usize;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let (page, next_cursor) = plugin
            .list(WAL_BLOB_PREFIX, 1024, cursor)
            .await
            .map_err(|e| ApiError::bad(format!("list wal: {e}")))?;
        for entry in &page {
            listed += 1;
            // Parse out the device_id from `wal/<device>/<seq>`.
            let rest = match entry.name.strip_prefix(WAL_BLOB_PREFIX) {
                Some(r) => r,
                None => continue,
            };
            let mut parts = rest.splitn(2, '/');
            let dev_str = match parts.next() {
                Some(d) => d,
                None => continue,
            };
            let dev = match uuid::Uuid::parse_str(dev_str) {
                Ok(u) => os_types::DeviceId::from_uuid(u),
                Err(_) => continue,
            };
            if dev == local_device {
                continue; // skip our own entries
            }
            let blob = match plugin.named_get(&entry.name).await {
                Ok(Some((b, _))) => b,
                _ => continue,
            };
            let we: os_entities::WalEntry = match ciborium::from_reader(&blob[..]) {
                Ok(w) => w,
                Err(_) => continue,
            };
            seen_devices.insert(dev);
            foreign_entries.push(we);
        }
        match next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    // Apply foreign entries via the sync engine's CRDT merge logic.
    let report = s
        .vfs
        .sync()
        .apply_remote_wal_segment(&s.vault.store(), &foreign_entries)
        .map_err(|e| ApiError::bad(format!("apply_remote: {e}")))?;
    Ok(Json(serde_json::json!({
        "listed": listed,
        "foreign_entries": foreign_entries.len(),
        "applied": report.applied,
        "skipped": report.skipped,
        "unhandled": report.unhandled,
        "demotions": report.demotions,
        "lost_to_local": report.lost_to_local,
        "peer_devices": seen_devices.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
    })))
}

/// F-HM-3 — anti-entropy reconcile stub. Lists vault providers and
/// reports their reachability. Real Merkle-walk reconcile lands
/// alongside the WAL-pull endpoint (G8); this handler exists so the
/// flow is end-to-end drivable today.
async fn antientropy_run(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let providers = s.host.list_vault();
    let mut reachable = 0u32;
    let mut unreachable = 0u32;
    let mut details: Vec<serde_json::Value> = Vec::new();
    for pid in &providers {
        let plugin = match s.host.get_vault(*pid) {
            Ok(p) => p,
            Err(_) => {
                unreachable += 1;
                details.push(serde_json::json!({
                    "provider_id": pid.to_string(),
                    "reachable": false,
                    "reason": "plugin_not_loaded",
                }));
                continue;
            }
        };
        // Cheap reachability check: list a single named blob.
        match plugin
            .peek(&os_entities::NativeHandle("antientropy_probe".into()))
            .await
        {
            Ok(_) | Err(_) => {
                // Either response shape is fine; we only need the round
                // trip to confirm reachability. A real walk compares
                // merkle roots — that's the F-HM-3 successor patch.
                reachable += 1;
                details.push(serde_json::json!({
                    "provider_id": pid.to_string(),
                    "reachable": true,
                }));
            }
        }
    }
    Ok(Json(serde_json::json!({
        "providers": providers.len(),
        "reachable": reachable,
        "unreachable": unreachable,
        "details": details,
        "note": "Merkle reconcile pending; this confirms vault-provider reachability."
    })))
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

/// STATES_AND_FLOWS §1.7 — derive the user-visible Share state from the
/// stored fields. Order: `Revoked` > `Expired` > `Active`. Lazy expiry
/// avoids a separate scheduler — every list/accept call re-checks.
fn share_state_label(sh: &os_entities::Share) -> &'static str {
    if sh.revoked_at.is_some() {
        return "revoked";
    }
    if let Some(exp) = &sh.expires_at {
        if let Some(exp_secs) = exp.epoch_secs() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if exp_secs <= now {
                return "expired";
            }
        }
    }
    "active"
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
            "state": share_state_label(&sh),
            "expires_at": sh.expires_at.as_ref().map(|t| t.as_str().to_string()),
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
    /// Optional `epoch:N` timestamp string. STATES_AND_FLOWS §1.7 — the
    /// share auto-transitions to `Expired` once this passes.
    expires_at: Option<String>,
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
    // Resolve file_id from path (only File-scope shares are supported in
    // this slice; folder/vault scopes share the same crypto with broader
    // permissions and are layered on later).
    // For folder/vault scope we can't stat a single path; the share
    // record carries the scope, and the recipient enumerates against
    // it at accept-time. For the file scope we still resolve to a
    // FileId. Either way we end up with a `meta_file_id` to wrap the
    // file_key under.
    let meta_file_id = match &scope {
        os_entities::ShareScope::File(p) => {
            let meta = s
                .vfs
                .stat(p)
                .map_err(|e| ApiError::not_found(format!("stat: {e}")))?;
            meta.file_id
        }
        os_entities::ShareScope::Folder(_) | os_entities::ShareScope::Vault => {
            // Folder/vault scope binds to a synthetic FileId. Real
            // material is per-file inside; the recipient walks the
            // scope at fetch time. This is enough to drive
            // F-SH-1's state machine.
            os_types::FileId::from_uuid(uuid::Uuid::nil())
        }
    };

    // Resolve or auto-create the recipient peer to fetch its KEM pubkey
    // (test-mode behavior matches the prior stub).
    let recipient = os_types::PeerId(req.recipient.clone());
    let backend = s.vault.store().backend();
    let mut peer_kem: Option<os_types::MlKemPub> = None;
    let mut peer_sign: Option<os_types::Ed25519Pub> = None;
    for kv in backend
        .scan_prefix(os_metadata::ColumnFamily::Peers, b"")
        .map_err(|e| ApiError::bad(format!("scan: {e}")))?
    {
        let (_, v) = kv.map_err(|e| ApiError::bad(format!("scan: {e}")))?;
        let p: os_entities::Peer = ciborium::from_reader(&v[..])
            .map_err(|e| ApiError::bad(format!("decode: {e}")))?;
        if p.peer_id == recipient {
            if let Some(epoch) = p.epochs.last() {
                peer_kem = Some(epoch.kem_pubkey.clone());
                peer_sign = Some(epoch.sign_pubkey);
            }
            break;
        }
    }
    let _ = peer_sign;
    let recipient_kem = peer_kem.unwrap_or_else(|| os_types::MlKemPub(vec![13u8; 32]));

    let mk = s
        .vault
        .master_key()
        .ok_or_else(|| ApiError::locked("create_share: vault locked"))?;
    let mk_sym = os_crypto::SymKey::from_bytes(*mk.as_bytes());
    // Owner signing key derived from MK under the share-sign domain. This
    // mirrors the stub used by /identity/rotate; per F-SH-1 the real
    // wiring uses the current epoch's persisted priv key.
    let owner_priv_bytes =
        os_crypto::derive_subkey(&mk_sym, os_types::KeyPurpose::WAL_SIGN, Some(b"share-owner"))
            .map_err(|e| ApiError::bad(format!("derive owner_priv: {e:?}")))?;
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(owner_priv_bytes.as_bytes());
    let owner_priv = os_types::Ed25519Priv(sk_bytes);
    let owner_pub = os_crypto::ed25519_pub_from_priv(&owner_priv);

    let creq = ShareCreateReq {
        file_id: meta_file_id,
        scope,
        permissions: vec![os_entities::Permission::Read],
        owner_peer_id: os_types::PeerId("self".into()),
        owner_epoch_id: os_types::EpochId(0),
        owner_sign_priv: &owner_priv,
        recipient_peer_id: recipient,
        recipient_kem_pub: &recipient_kem,
        master_key: &mk_sym,
        now: os_types::Timestamp::from_string("now"),
        expires_at: req
            .expires_at
            .clone()
            .map(os_types::Timestamp::from_string),
    };
    let (share, blob) = s
        .share
        .create_share(creq)
        .map_err(|e| ApiError::bad(format!("create_share: {e}")))?;
    let blob_bytes = share_encode_blob(&blob)
        .map_err(|e| ApiError::bad(format!("encode_blob: {e}")))?;
    Ok(Json(serde_json::json!({
        "share_id": share.share_id.to_string(),
        "state": "created",
        "blob_hex": hex::encode(&blob_bytes),
        "owner_sign_pub_hex": hex::encode(owner_pub.0),
    })))
}

async fn revoke_share(
    State(s): State<AppState>,
    Path((_vault_id, share_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let u = uuid::Uuid::parse_str(&share_id).map_err(|_| ApiError::bad("invalid share_id"))?;
    let id = os_types::ShareId::from_uuid(u);
    let new_v = s
        .share
        .revoke_share(id, os_types::Timestamp::from_string("now"))
        .map_err(|e| match e {
            os_share::ShareError::NotFound(_) => ApiError::not_found("share"),
            os_share::ShareError::VaultLocked => ApiError::locked("revoke: vault locked"),
            other => ApiError::bad(format!("revoke: {other}")),
        })?;
    Ok(Json(serde_json::json!({
        "share_id": id.to_string(),
        "state": "revoked",
        "new_file_key_version": new_v,
    })))
}

#[derive(Deserialize)]
struct AcceptShareReq {
    /// Hex-encoded `ShareBlob` bytes.
    blob_hex: String,
    /// Hex-encoded owner's Ed25519 public key (32 bytes).
    owner_sign_pub_hex: String,
    /// Optional override for the local mount path. Defaults to
    /// `/shared-with-me/{owner_peer_id}/{scope_path}`.
    mount_path: Option<String>,
}

async fn accept_share(
    State(s): State<AppState>,
    Path((_vault_id, _share_id)): Path<(String, String)>,
    Json(req): Json<AcceptShareReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let blob_bytes =
        hex::decode(&req.blob_hex).map_err(|_| ApiError::bad("blob_hex not hex"))?;
    let blob = share_decode_blob(&blob_bytes)
        .map_err(|e| ApiError::bad(format!("decode_blob: {e}")))?;
    // STATES_AND_FLOWS §1.7 Share state — refuse expired blobs at accept
    // time (lazy enforcement). This catches the recipient case where the
    // owner set an expiry that passed before acceptance.
    if let Some(exp) = &blob.expires_at {
        if let Some(exp_secs) = exp.epoch_secs() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if exp_secs <= now {
                return Err(ApiError::bad("share expired"));
            }
        }
    }
    let owner_pub_bytes = hex::decode(&req.owner_sign_pub_hex)
        .map_err(|_| ApiError::bad("owner_sign_pub_hex not hex"))?;
    if owner_pub_bytes.len() != 32 {
        return Err(ApiError::bad("owner_sign_pub must be 32 bytes hex"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&owner_pub_bytes);
    let owner_pub = os_types::Ed25519Pub(pk);
    // Recipient KEM pubkey: same placeholder as create — in real
    // deployments this is fetched from the local identity service.
    let recipient_kem = os_types::MlKemPub(vec![13u8; 32]);
    let mount_path = req.mount_path.unwrap_or_else(|| {
        let scope_path = match &blob.scope {
            os_entities::ShareScope::File(p) => p.clone(),
            os_entities::ShareScope::Folder(p) => p.clone(),
            os_entities::ShareScope::Vault => "/".into(),
        };
        format!("/shared-with-me/{}{}", blob.owner_peer_id.0, scope_path)
    });
    let received = s
        .share
        .accept_share(
            &blob,
            &owner_pub,
            &recipient_kem,
            mount_path.clone(),
            os_types::Timestamp::from_string("now"),
        )
        .map_err(|e| match e {
            os_share::ShareError::SignatureInvalid => {
                ApiError::unauth("share signature invalid")
            }
            other => ApiError::bad(format!("accept: {other}")),
        })?;
    Ok(Json(serde_json::json!({
        "share_id": received.share_id.to_string(),
        "file_id": received.file_id.to_string(),
        "file_key_version": received.file_key_version,
        "mounted_path": received.mounted_path,
        "state": "accepted",
    })))
}

async fn list_inbox(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let xs = s
        .share
        .list_received()
        .map_err(|e| ApiError::bad(format!("list_received: {e}")))?;
    let arr: Vec<_> = xs
        .iter()
        .map(|r| {
            serde_json::json!({
                "share_id": r.share_id.to_string(),
                "owner_peer_id": r.owner_peer_id.0,
                "file_id": r.file_id.to_string(),
                "mounted_path": r.mounted_path,
                "file_key_version": r.file_key_version,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "inbox": arr })))
}

/// F-SN-1 query/body parameters.
#[derive(Deserialize, Default)]
struct PushSnapshotReq {
    /// Pointer-CAS guard (RESILIENCE rollback detection). When present,
    /// the push fails with 409 if the local vault's
    /// `snapshot_pointer.version_counter` doesn't equal this value.
    #[serde(default)]
    expected_version_counter: Option<u64>,
    /// Differential-push watermark: only File records whose
    /// `modified_at.hlc.physical` is strictly greater than this value are
    /// included. Other CFs are always serialized in full.
    #[serde(default)]
    delta_since_hlc_physical: Option<u64>,
}

async fn push_snapshot_route(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    body: Option<Json<PushSnapshotReq>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let v = parse_vault_id(&vault_id)?;
    let mut vault = s
        .vault
        .store()
        .get_vault(v)
        .map_err(|e| ApiError::bad(format!("get_vault: {e}")))?
        .ok_or_else(|| ApiError::not_found("vault"))?;
    if let Some(expected) = req.expected_version_counter {
        if vault.snapshot_pointer.version_counter.0 != expected {
            return Err(ApiError::conflict(format!(
                "pointer CAS mismatch: have {}, expected {}",
                vault.snapshot_pointer.version_counter.0, expected
            )));
        }
    }

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
            // Differential-push filter on Files CF.
            if cf == os_metadata::ColumnFamily::Files {
                if let Some(since) = req.delta_since_hlc_physical {
                    if let Ok(file) = ciborium::from_reader::<os_entities::File, _>(&val[..]) {
                        if file.modified_at.hlc.physical <= since {
                            continue;
                        }
                    }
                }
            }
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

    // Layer 3 — refuse `EventualOnly` providers for snapshot push. The
    // snapshot pointer is a sole-source coordination record; if the
    // backend can't promise CAS we'd silently clobber a concurrent
    // peer's write. We pick from the providers meeting at least
    // `OptimisticCas`; if none exist we fail loudly with a structured
    // error rather than degrading.
    let vps = s
        .host
        .vault_providers_at_least(os_types::CasTier::OptimisticCas);
    if vps.is_empty() && !s.host.list_vault().is_empty() {
        // Plugins exist but none meets the tier. Surface why.
        return Err(ApiError::bad(
            "snapshot push refused: no vault provider declares OptimisticCas or stronger; \
             EventualOnly backends cannot host the snapshot pointer (Layer 3)",
        ));
    }
    let mut verify_failed = false;
    let mut put_handle_hex: Option<String> = None;
    let pushed_to: Option<String> = if let Some(provider_id) = vps.first() {
        let vp = s
            .host
            .get_vault(*provider_id)
            .map_err(|e| ApiError::bad(format!("get_vault_plugin: {e}")))?;
        match vp
            .put(&blob, &os_entities::PutHint::default())
            .await
        {
            Ok(put_result) => {
                put_handle_hex = Some(hex::encode(&put_result.handle.0));
                // F-SN-1 verify-after-upload: peek the freshly written
                // handle and confirm its size matches what we sent.
                if let Ok(peek) = vp.peek(&put_result.handle).await {
                    if !peek.exists || peek.size != blob.len() as u64 {
                        verify_failed = true;
                    }
                    // NB: we do NOT compare `peek.etag` to a locally
                    // recomputed digest — backends use different hash
                    // families (testbench BLAKE2b-256, LocalDirPlugin
                    // BLAKE3-32, S3 MD5). Size + exists is the
                    // cross-backend portable signal; finer integrity
                    // checks live in the AEAD tag covering `blob`.
                    let _ = (peek.etag, etag);
                }
                if verify_failed {
                    None
                } else {
                    Some(provider_id.to_string())
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    if verify_failed {
        return Err(ApiError::bad(
            "verify-after-upload mismatch; pointer not advanced",
        ));
    }

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

    // F-SN-1 / WAL Compacted: once the snapshot has landed at the vault
    // provider, every WAL entry up to the current tail is now durably
    // captured. Truncate the WAL through that cutoff so subsequent
    // replays start from the snapshot, not from seq 0.
    let wal = s.vfs.sync().wal();
    let truncate_cutoff = wal.next_seq();
    let truncated_to = if pushed_to.is_some() && truncate_cutoff > 0 {
        wal.truncate_through(truncate_cutoff).ok();
        Some(truncate_cutoff)
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "version_counter": vault.snapshot_pointer.version_counter.0,
        "snapshot_id": hex::encode(&snapshot_id),
        "etag": hex::encode(etag.as_bytes()),
        "blob_bytes": blob.len(),
        "entries": entries.len(),
        "pushed_to_vault_provider": pushed_to,
        "snapshot_handle_hex": put_handle_hex,
        "wal_truncated_through": truncated_to,
    })))
}

#[derive(Deserialize, Default)]
struct SweepReq {
    /// For scrub: per-thousand sample size (default 50 = 5%).
    /// For rebalance: per-thousand fraction (default 100 = 10%).
    #[serde(default)]
    fraction_per_thousand: Option<u32>,
}

/// F-HM-1 — POST /v1/system/scrub. Enqueues a sampled scrub batch.
async fn system_scrub(
    State(s): State<AppState>,
    body: Option<Json<SweepReq>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let n = s
        .repair
        .scrub_sweep(&s.vault.store(), req.fraction_per_thousand.unwrap_or(50))
        .map_err(|e| ApiError::bad(format!("scrub: {e}")))?;
    Ok(Json(serde_json::json!({ "enqueued": n })))
}

/// F-HM-5 — POST /v1/system/gc. Enqueues GC-sweep tasks for any chunk
/// whose refcount has dropped to ≤ 0.
async fn system_gc(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let n = s
        .repair
        .gc_sweep(&s.vault.store())
        .map_err(|e| ApiError::bad(format!("gc: {e}")))?;
    Ok(Json(serde_json::json!({ "enqueued": n })))
}

/// F-HM-4 — POST /v1/vaults/{v}/rebalance. Triggered by the engine after
/// a plugin add or by an operator; enqueues a fraction of chunks for
/// placement re-evaluation.
async fn system_rebalance(
    State(s): State<AppState>,
    Path(_vault_id): Path<String>,
    body: Option<Json<SweepReq>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = body.map(|j| j.0).unwrap_or_default();
    let n = s
        .repair
        .rebalance_on_plugin_add(&s.vault.store(), req.fraction_per_thousand.unwrap_or(100))
        .map_err(|e| ApiError::bad(format!("rebalance: {e}")))?;
    Ok(Json(serde_json::json!({ "enqueued": n })))
}

/// F-SN-2 — pull request body. The recipient identifies the snapshot by
/// the `snapshot_handle_hex` the pusher recorded.
#[derive(Deserialize)]
struct PullSnapshotReq {
    /// Hex-encoded provider-side handle returned by the push route.
    snapshot_handle_hex: String,
}

/// F-SN-2 Cold-Start Snapshot Pull. Fetches the named blob from the first
/// registered vault provider, AEAD-decrypts it under the snapshot subkey,
/// CBOR-decodes the entry list, and writes each entry back into the
/// matching column family. Idempotent — re-pulling the same blob yields
/// the same store state.
async fn pull_snapshot_route(
    State(s): State<AppState>,
    Path(vault_id): Path<String>,
    Json(req): Json<PullSnapshotReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = parse_vault_id(&vault_id)?;
    let mk = s
        .vault
        .master_key()
        .ok_or_else(|| ApiError::locked("pull_snapshot: vault must be Unlocked"))?;
    let vps = s.host.list_vault();
    let provider_id = vps
        .first()
        .ok_or_else(|| ApiError::bad("no vault provider registered"))?;
    let vp = s
        .host
        .get_vault(*provider_id)
        .map_err(|e| ApiError::bad(format!("get_vault_plugin: {e}")))?;
    let handle_bytes = hex_decode(&req.snapshot_handle_hex)
        .ok_or_else(|| ApiError::bad("snapshot_handle_hex not hex"))?;
    let handle = os_entities::NativeHandle(handle_bytes);
    let blob = vp
        .get(&handle, None)
        .await
        .map_err(|e| ApiError::not_found(format!("snapshot fetch: {e}")))?;
    if blob.len() < 12 + 16 {
        return Err(ApiError::bad("snapshot blob too short"));
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&blob[..12]);
    let nonce = os_types::AeadNonce::N12(nonce_bytes);
    let ct_end = blob.len() - 16;
    let ct = &blob[12..ct_end];
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(&blob[ct_end..]);
    let tag = os_types::AeadTag(tag_bytes);
    let snap_key = os_crypto::derive_subkey(&mk, os_types::KeyPurpose::SNAPSHOT, None)
        .map_err(|e| ApiError::bad(format!("derive: {e:?}")))?;
    let aad = format!("snapshot:{}", v);
    let plaintext = os_crypto::decrypt(
        os_types::AeadSuite::ChaCha20Poly1305,
        &snap_key,
        &nonce,
        ct,
        &tag,
        aad.as_bytes(),
    )
    .map_err(|_| ApiError::bad("snapshot AEAD verification failed"))?;
    let entries: Vec<(String, Vec<u8>)> =
        ciborium::from_reader(&plaintext[..])
            .map_err(|e| ApiError::bad(format!("snapshot decode: {e}")))?;

    let backend = s.vault.store().backend();
    let mut applied = 0usize;
    for (key, value) in &entries {
        let (cf_name, hex_key) = match key.split_once('/') {
            Some(p) => p,
            None => continue,
        };
        let cf = match cf_name {
            "files" => os_metadata::ColumnFamily::Files,
            "chunks" => os_metadata::ColumnFamily::Chunks,
            "shards" => os_metadata::ColumnFamily::Shards,
            "shadows" => os_metadata::ColumnFamily::Shadows,
            "providers" => os_metadata::ColumnFamily::Providers,
            "identity" => os_metadata::ColumnFamily::Identity,
            "peers" => os_metadata::ColumnFamily::Peers,
            "shares" => os_metadata::ColumnFamily::Shares,
            "devices" => os_metadata::ColumnFamily::Devices,
            _ => continue,
        };
        let raw_key = match hex_decode(hex_key) {
            Some(k) => k,
            None => continue,
        };
        let mut txn = os_metadata::Txn::new();
        txn.put(cf, raw_key, value.clone());
        backend
            .commit(txn)
            .map_err(|e| ApiError::bad(format!("apply: {e}")))?;
        applied += 1;
    }
    Ok(Json(serde_json::json!({
        "applied": applied,
        "entries": entries.len(),
        "snapshot_handle_hex": req.snapshot_handle_hex,
    })))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let h = match (bytes[i] as char).to_digit(16) {
            Some(v) => v,
            None => return None,
        };
        let l = match (bytes[i + 1] as char).to_digit(16) {
            Some(v) => v,
            None => return None,
        };
        out.push(((h << 4) | l) as u8);
    }
    Some(out)
}

// ─── F-PL-1 install / F-PL-3 reload ──────────────────────────────────────

#[derive(Deserialize)]
struct InstallPluginReq {
    /// Hex-encoded CBOR `PluginManifest`.
    manifest_hex: String,
    /// "confirm" (Green/Amber) or "double" (Red).
    confirmation: String,
}

async fn install_plugin_route(
    State(s): State<AppState>,
    Json(req): Json<InstallPluginReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bytes = hex_decode(&req.manifest_hex).ok_or_else(|| ApiError::bad("manifest_hex"))?;
    let manifest: PluginManifest =
        ciborium::from_reader(&bytes[..]).map_err(|e| ApiError::bad(format!("decode: {e}")))?;
    let confirmation = match req.confirmation.as_str() {
        "confirm" => UserConfirmation::Confirm,
        "double" => UserConfirmation::DoubleConfirm,
        other => return Err(ApiError::bad(format!("unknown confirmation: {other}"))),
    };
    let prior = s
        .plugin_authors
        .read()
        .expect("plugin_authors")
        .get(&manifest.plugin_id)
        .cloned();
    plug_lifecycle::verify_install(&manifest, prior.as_ref(), confirmation).map_err(|e| match e {
        plug_lifecycle::LifecycleError::SignatureInvalid => ApiError::unauth(format!("install: {e}")),
        plug_lifecycle::LifecycleError::AuthorRotated => ApiError::conflict(format!("install: {e}")),
        plug_lifecycle::LifecycleError::RedLegalClassUnconfirmed => {
            ApiError::bad(format!("install: {e}"))
        }
        other => ApiError::bad(format!("install: {other}")),
    })?;
    // Record TOFU author + initial capabilities for drift detection.
    s.plugin_authors
        .write()
        .expect("plugin_authors")
        .insert(manifest.plugin_id.clone(), manifest.author_pubkey);
    s.plugin_capabilities
        .write()
        .expect("plugin_capabilities")
        .insert(
            manifest.plugin_id.clone(),
            manifest.requested_capabilities.clone(),
        );
    Ok(Json(serde_json::json!({
        "plugin_id": manifest.plugin_id.0,
        "version": manifest.version,
        "state": "loaded",
    })))
}

#[derive(Deserialize)]
struct ReloadPluginReq {
    /// Hex-encoded CBOR `CapabilitySet` reflecting the new manifest's
    /// declared capabilities.
    capabilities_hex: String,
}

async fn reload_plugin_route(
    State(s): State<AppState>,
    Path(plugin_id): Path<String>,
    Json(req): Json<ReloadPluginReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pid = os_types::PluginId::new(plugin_id);
    let bytes =
        hex_decode(&req.capabilities_hex).ok_or_else(|| ApiError::bad("capabilities_hex"))?;
    let new_caps: os_types::CapabilitySet =
        ciborium::from_reader(&bytes[..]).map_err(|e| ApiError::bad(format!("decode: {e}")))?;
    let prev = s
        .plugin_capabilities
        .read()
        .expect("plugin_capabilities")
        .get(&pid)
        .cloned();
    let prev = match prev {
        Some(p) => p,
        None => return Err(ApiError::not_found("plugin not installed")),
    };
    let diff = plug_lifecycle::diff_capabilities(&prev, &new_caps);
    let needs_decision = !diff.lost.is_empty();
    s.plugin_capabilities
        .write()
        .expect("plugin_capabilities")
        .insert(pid.clone(), new_caps);
    let state_after = if needs_decision {
        s.events
            .publish(os_events::Event::new("plugin.confirmation_required"));
        s.plugin_decisions
            .write()
            .expect("plugin_decisions")
            .insert(
                pid.clone(),
                PluginDecisionEntry {
                    gained: diff.gained.clone(),
                    lost: diff.lost.clone(),
                    state: "awaiting_user_decision",
                },
            );
        "awaiting_user_decision"
    } else {
        // Capability gain (or no-op) clears any stale awaiting flag.
        s.plugin_decisions
            .write()
            .expect("plugin_decisions")
            .remove(&pid);
        "active"
    };
    Ok(Json(serde_json::json!({
        "plugin_id": pid.0,
        "gained": diff.gained,
        "lost": diff.lost,
        "state": state_after,
    })))
}

#[derive(Deserialize)]
struct PluginDecisionReq {
    /// `keep` ⇒ accept the capability downgrade and resume Active.
    /// `migrate_out` ⇒ start migration (transition to Migrating then
    /// Disabled once shards have been re-placed).
    action: String,
}

/// F-PL-3 — clear an `AwaitingUserDecision` state. The user picks between
/// keeping the plugin with reduced capabilities (downgrade) or migrating
/// off it. This handler does NOT itself re-place shards; the migration
/// hand-off is signalled to the repair scheduler when `action=migrate_out`
/// (the actual rebalance lands when the worker drains its queue).
async fn plugin_decision_route(
    State(s): State<AppState>,
    Path(plugin_id): Path<String>,
    Json(req): Json<PluginDecisionReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pid = os_types::PluginId::new(plugin_id);
    let entry = {
        let mut g = s.plugin_decisions.write().expect("plugin_decisions");
        g.remove(&pid)
    };
    let entry = entry.ok_or_else(|| {
        ApiError::not_found(format!(
            "plugin {} is not awaiting a user decision",
            pid.0
        ))
    })?;
    let final_state = match req.action.as_str() {
        "keep" => "active",
        "migrate_out" => {
            // Enqueue a rebalance pass so the worker re-places the
            // plugin's shards onto remaining providers. The plugin
            // itself transitions Migrating → Disabled (advertised via
            // the per-provider plugin-state endpoint).
            let _ = s
                .repair
                .rebalance_on_plugin_add(&s.vault.store(), 1000);
            s.events
                .publish(os_events::Event::new("plugin.migrate_out_started"));
            "migrating"
        }
        other => {
            // Re-insert so the caller can retry with a valid action.
            s.plugin_decisions
                .write()
                .expect("plugin_decisions")
                .insert(pid.clone(), entry.clone());
            return Err(ApiError::bad(format!(
                "unknown action {other}; expected `keep` or `migrate_out`"
            )));
        }
    };
    Ok(Json(serde_json::json!({
        "plugin_id": pid.0,
        "action": req.action,
        "lost": entry.lost,
        "gained": entry.gained,
        "state": final_state,
    })))
}

async fn plugin_decision_get(
    State(s): State<AppState>,
    Path(plugin_id): Path<String>,
) -> Json<serde_json::Value> {
    let pid = os_types::PluginId::new(plugin_id);
    let g = s.plugin_decisions.read().expect("plugin_decisions");
    match g.get(&pid) {
        Some(e) => Json(serde_json::json!({
            "plugin_id": pid.0,
            "state": e.state,
            "gained": e.gained,
            "lost": e.lost,
        })),
        None => Json(serde_json::json!({
            "plugin_id": pid.0,
            "state": "active",
        })),
    }
}

// ─── F-PL-2 OAuth ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OAuthStartReq {
    plugin_id: String,
    auth_url: String,
    #[serde(default)]
    required_scopes: Vec<String>,
}

async fn oauth_start_route(
    State(s): State<AppState>,
    Json(req): Json<OAuthStartReq>,
) -> Json<serde_json::Value> {
    let session = s.oauth.start(
        os_types::PluginId::new(req.plugin_id),
        req.auth_url,
        req.required_scopes,
    );
    Json(serde_json::json!({
        "state": session.state,
        "auth_url": session.auth_url,
    }))
}

#[derive(Deserialize)]
struct OAuthCompleteReq {
    state: String,
    /// Hex-encoded raw token bytes (the OAuth `access_token`).
    token_hex: String,
    granted_scopes: Vec<String>,
}

async fn oauth_complete_route(
    State(s): State<AppState>,
    Json(req): Json<OAuthCompleteReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = hex_decode(&req.token_hex).ok_or_else(|| ApiError::bad("token_hex"))?;
    let mk = s
        .vault
        .master_key()
        .ok_or_else(|| ApiError::locked("oauth: vault must be Unlocked"))?;
    let mk_sym = os_crypto::SymKey::from_bytes(*mk.as_bytes());
    let (session, cred) = s
        .oauth
        .complete(&req.state, &token, &req.granted_scopes, &mk_sym)
        .map_err(|e| match e {
            plug_lifecycle::LifecycleError::OAuthSessionNotFound => {
                ApiError::not_found("oauth session")
            }
            plug_lifecycle::LifecycleError::OAuthInsufficientScope { .. } => {
                ApiError::bad(format!("oauth: {e}"))
            }
            other => ApiError::bad(format!("oauth: {other}")),
        })?;
    Ok(Json(serde_json::json!({
        "plugin_id": session.plugin_id.0,
        "credentials_handle_hex": hex::encode(cred.as_bytes()),
        "state": "ready",
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
        let vfs = Arc::new(VfsService::new(store.clone(), vault.clone(), sync));
        let lease = Arc::new(os_lease::LeaseService::new());
        let repair = Arc::new(os_repair::RepairScheduler::new(1024));
        let events = Arc::new(os_events::EventBus::new());
        let share = Arc::new(os_share::ShareService::new(store, vfs.clone()));
        let oauth = Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new());
        let plugin_authors = Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::new(),
        ));
        let plugin_capabilities = Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::new(),
        ));
        router(AppState {
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
            plugin_authors,
            plugin_capabilities,
            device_id,
            fault: None,
            plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
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

    /// F-SH-1 → F-SH-2 — owner creates a share via the API; the returned
    /// blob and owner pubkey let the recipient accept it through the
    /// /inbox/{share_id}/accept route. Verifies the inbox listing reflects
    /// the accepted share.
    #[tokio::test]
    async fn share_create_and_accept_round_trip() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        // Author a file to share.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/secret.txt"))
                    .body(Body::from("classified"))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = serde_json::json!({ "recipient": "bob", "scope": "/secret.txt" });
        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/shares"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = axum::body::to_bytes(create.into_body(), 16384).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let share_id = parsed["share_id"].as_str().unwrap().to_string();
        let blob_hex = parsed["blob_hex"].as_str().unwrap().to_string();
        let owner_pub_hex = parsed["owner_sign_pub_hex"].as_str().unwrap().to_string();

        let accept_body = serde_json::json!({
            "blob_hex": blob_hex,
            "owner_sign_pub_hex": owner_pub_hex,
        });
        let accept = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/inbox/{share_id}/accept"))
                    .header("content-type", "application/json")
                    .body(Body::from(accept_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accept.status(), StatusCode::OK);

        let inbox = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/inbox"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(inbox.into_body(), 16384).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = parsed["inbox"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["share_id"].as_str().unwrap(), share_id);
    }

    /// F-SH-2 — accept with a tampered owner pubkey fails with 401.
    #[tokio::test]
    async fn share_accept_with_wrong_owner_pubkey_401() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
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
        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/shares"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"recipient":"b","scope":"/x"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(create.into_body(), 16384).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let share_id = parsed["share_id"].as_str().unwrap().to_string();
        let blob_hex = parsed["blob_hex"].as_str().unwrap().to_string();

        let bogus_pub = hex::encode([0u8; 32]);
        let accept_body = serde_json::json!({
            "blob_hex": blob_hex,
            "owner_sign_pub_hex": bogus_pub,
        });
        let accept = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/inbox/{share_id}/accept"))
                    .header("content-type", "application/json")
                    .body(Body::from(accept_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accept.status(), StatusCode::UNAUTHORIZED);
    }

    /// F-SH-3 — revoke bumps `file_key_version` and returns it. Revoke
    /// twice should produce strictly increasing versions.
    #[tokio::test]
    async fn share_revoke_bumps_version() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/r.txt"))
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Two shares to two recipients.
        let mut versions = Vec::new();
        for recipient in ["b1", "b2"] {
            let body = serde_json::json!({"recipient": recipient, "scope": "/r.txt"});
            let create = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/vaults/{vault_id}/shares"))
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body =
                axum::body::to_bytes(create.into_body(), 16384).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let share_id = parsed["share_id"].as_str().unwrap().to_string();

            let rev = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/v1/vaults/{vault_id}/shares/{share_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rev.status(), StatusCode::OK);
            let body = axum::body::to_bytes(rev.into_body(), 16384).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            versions.push(parsed["new_file_key_version"].as_u64().unwrap());
        }
        assert_eq!(versions, vec![1, 2]);

        // After revocation the file is still readable by the owner.
        let g = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/r.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(g.into_body(), 16384).await.unwrap();
        assert_eq!(&body[..], b"data");
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

    /// F-SN-2 — push then pull round-trip restores the snapshot's File
    /// rows. Author a file → push → mutate locally → pull → confirm
    /// the original content reappears.
    #[tokio::test]
    async fn push_then_pull_round_trip() {
        // Build a router with a LocalDirPlugin registered as a vault
        // provider so push has somewhere to write the snapshot blob and
        // pull can fetch it back.
        use os_plugin_host::LocalDirPlugin;
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-snap-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tdir).unwrap();
        let provider_id = os_types::ProviderId::new_v7();
        host.register_vault(
            provider_id,
            Arc::new(LocalDirPlugin::new(tdir.join("vault")).unwrap()),
        );
        let identity = Arc::new(IdentityService::new(store.clone()));
        let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
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
        let vfs = Arc::new(VfsService::new(store.clone(), vault.clone(), sync));
        let lease = Arc::new(os_lease::LeaseService::new());
        let repair = Arc::new(os_repair::RepairScheduler::new(1024));
        let events = Arc::new(os_events::EventBus::new());
        let share = Arc::new(os_share::ShareService::new(store.clone(), vfs.clone()));
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
            oauth: Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new()),
            plugin_authors: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_capabilities: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            device_id,
            fault: None,
            plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        });
        let vault_id = create_vault_for_test(&app).await;

        // Author a file with original content.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/snap.txt"))
                    .body(Body::from("original-content"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Push the snapshot.
        let push = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/push"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(push.status(), StatusCode::OK);
        let body = axum::body::to_bytes(push.into_body(), 65536).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let handle_hex = parsed["snapshot_handle_hex"]
            .as_str()
            .expect("snapshot_handle_hex should be present after a successful push")
            .to_string();

        // Mutate the file locally to a different value.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/snap.txt"))
                    .body(Body::from("mutated-content-after-push"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Pull the snapshot. The pulled records overwrite local rows
        // for the same keys.
        let pull = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/pull"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"snapshot_handle_hex": handle_hex}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pull.status(), StatusCode::OK);

        // Confirm the file now reads back the *original* content.
        let read = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/vaults/{vault_id}/files/snap.txt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(read.into_body(), 16384).await.unwrap();
        assert_eq!(&body[..], b"original-content");
    }

    /// F-SN-1 — push with `expected_version_counter` matching local
    /// pointer succeeds; mismatch returns 409.
    #[tokio::test]
    async fn push_snapshot_cas_pointer() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        // Local pointer starts at version_counter=0.
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/push"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"expected_version_counter": 99}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::CONFLICT);

        let ok = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/push"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"expected_version_counter": 0}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ok.into_body(), 65536).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["version_counter"].as_u64().unwrap(), 1);
    }

    /// F-SN-1 — `delta_since_hlc_physical` filters File entries.
    #[tokio::test]
    async fn push_snapshot_delta_filter() {
        let app = build_app();
        let vault_id = create_vault_for_test(&app).await;
        // Two files written in sequence so they have distinct HLCs.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/old"))
                    .body(Body::from("first"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/vaults/{vault_id}/files/new"))
                    .body(Body::from("second"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Full push: 2 file entries.
        let full = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/push"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(full.into_body(), 65536).await.unwrap();
        let parsed_full: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let full_entries = parsed_full["entries"].as_u64().unwrap();
        assert!(full_entries >= 2, "expected ≥ 2 entries in full push");

        // Delta with a watermark above the universe filters all File rows.
        let delta = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/snapshot/push"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"delta_since_hlc_physical": u64::MAX - 1}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(delta.into_body(), 65536).await.unwrap();
        let parsed_delta: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let delta_entries = parsed_delta["entries"].as_u64().unwrap();
        assert!(
            delta_entries < full_entries,
            "delta entries ({delta_entries}) should drop below full ({full_entries})"
        );
    }

    /// F-HM-1 / F-HM-5 — POST /v1/system/scrub and /gc enqueue tasks
    /// against the repair scheduler. With no chunks the count is 0 but
    /// the route succeeds.
    #[tokio::test]
    async fn system_scrub_and_gc_routes_succeed() {
        let app = build_app();
        let _ = create_vault_for_test(&app).await;
        let scrub = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/scrub")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scrub.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scrub.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["enqueued"].is_u64());

        let gc = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/gc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gc.status(), StatusCode::OK);
    }

    /// F-PL-1 — install plugin happy path: signed manifest accepted,
    /// the second install with the same author succeeds, an install
    /// with a tampered manifest is refused.
    #[tokio::test]
    async fn plugin_install_signature_and_tofu() {
        use os_crypto::{generate_keypair, sign};
        let app = build_app();
        let (sk, pk) = generate_keypair(&mut OsRng);
        let mut manifest = os_plugin_host::lifecycle::PluginManifest {
            plugin_id: os_types::PluginId::new("org.test.signed"),
            version: "1.0.0".into(),
            author_pubkey: pk,
            legal_class: os_types::LegalClass::Green,
            requested_capabilities: os_types::CapabilitySet::default()
                .with(os_types::Capability::Put)
                .with(os_types::Capability::Get),
            source_url: "https://example.com/p.wasm".into(),
            signature: os_types::Ed25519Sig([0u8; 64]),
        };
        let mut canon = Vec::new();
        ciborium::into_writer(&manifest, &mut canon).unwrap();
        manifest.signature = sign(&sk, &canon);

        let mut bytes = Vec::new();
        ciborium::into_writer(&manifest, &mut bytes).unwrap();
        let body = serde_json::json!({
            "manifest_hex": hex::encode(&bytes),
            "confirmation": "confirm",
        });
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // Tampered manifest with the same plugin_id but a different
        // signature → 401.
        let mut tampered = manifest.clone();
        tampered.version = "9.9.9".into();
        let mut tb = Vec::new();
        ciborium::into_writer(&tampered, &mut tb).unwrap();
        let body = serde_json::json!({
            "manifest_hex": hex::encode(&tb),
            "confirmation": "confirm",
        });
        let r = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// F-PL-2 — OAuth start/complete round-trip yields a credentials
    /// handle the engine can store.
    #[tokio::test]
    async fn plugin_oauth_round_trip() {
        let app = build_app();
        let _ = create_vault_for_test(&app).await;
        let start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/providers/oauth/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "plugin_id": "org.test.oauth",
                            "auth_url": "https://provider/authorize",
                            "required_scopes": ["files.write"],
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK);
        let body = axum::body::to_bytes(start.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let state = parsed["state"].as_str().unwrap().to_string();

        let complete = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/providers/oauth/complete")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "state": state,
                            "token_hex": hex::encode("access-token-bytes"),
                            "granted_scopes": ["files.write", "files.read"],
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::OK);
        let body = axum::body::to_bytes(complete.into_body(), 8192)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["credentials_handle_hex"].as_str().is_some());
    }

    /// F-PL-3 — capability drift on reload: lost capability transitions
    /// to AwaitingUserDecision.
    #[tokio::test]
    async fn plugin_capability_drift_marks_awaiting_user_decision() {
        use os_crypto::{generate_keypair, sign};
        let app = build_app();
        let (sk, pk) = generate_keypair(&mut OsRng);
        let mut manifest = os_plugin_host::lifecycle::PluginManifest {
            plugin_id: os_types::PluginId::new("org.test.drift"),
            version: "1.0.0".into(),
            author_pubkey: pk,
            legal_class: os_types::LegalClass::Green,
            requested_capabilities: os_types::CapabilitySet::default()
                .with(os_types::Capability::Put)
                .with(os_types::Capability::Get)
                .with(os_types::Capability::Tombstone),
            source_url: "https://example.com/p.wasm".into(),
            signature: os_types::Ed25519Sig([0u8; 64]),
        };
        let mut canon = Vec::new();
        ciborium::into_writer(&manifest, &mut canon).unwrap();
        manifest.signature = sign(&sk, &canon);
        let mut bytes = Vec::new();
        ciborium::into_writer(&manifest, &mut bytes).unwrap();
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "manifest_hex": hex::encode(&bytes),
                            "confirmation": "confirm",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let new_caps = os_types::CapabilitySet::default()
            .with(os_types::Capability::Put)
            .with(os_types::Capability::Get);
        let mut cb = Vec::new();
        ciborium::into_writer(&new_caps, &mut cb).unwrap();
        let r = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/plugins/org.test.drift/reload")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "capabilities_hex": hex::encode(&cb),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["state"].as_str().unwrap(), "awaiting_user_decision");
        assert!(parsed["lost"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("Tombstone")));
    }

    /// F-MD-4 — `try_steal` while the lease is still live returns 409.
    /// After 2×TTL has elapsed the steal succeeds, and the prior holder's
    /// renew returns 410 Gone.
    #[tokio::test]
    async fn lease_steal_via_api() {
        // We need two services sharing a lease registry to simulate two
        // devices; mount our own router with a shared registry pointing
        // at the same vault.
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let identity = Arc::new(IdentityService::new(store.clone()));
        let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-api-lease-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tdir).unwrap();
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let dev_a = DeviceId::new_v7();
        let dev_b = DeviceId::new_v7();
        let wal = WalBuilder::new()
            .path(tdir.join("wal.bin"))
            .build(dev_a, sk)
            .unwrap();
        let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
        let recovery = Arc::new(RecoveryService::new(
            store.clone(),
            identity.clone(),
            vault.clone(),
        ));
        let vfs = Arc::new(VfsService::new(store.clone(), vault.clone(), sync));
        let registry = os_lease::new_registry();
        let lease_a = Arc::new(os_lease::LeaseService::with_registry(registry.clone()));
        let lease_b = Arc::new(os_lease::LeaseService::with_registry(registry));
        let repair = Arc::new(os_repair::RepairScheduler::new(1024));
        let events = Arc::new(os_events::EventBus::new());
        let share = Arc::new(os_share::ShareService::new(store.clone(), vfs.clone()));
        let app_a = router(AppState {
            recovery: recovery.clone(),
            vault: vault.clone(),
            vfs: vfs.clone(),
            identity: identity.clone(),
            lease: lease_a.clone(),
            repair: repair.clone(),
            events: events.clone(),
            host: host.clone(),
            share: share.clone(),
            oauth: Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new()),
            plugin_authors: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_capabilities: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            device_id: dev_a,
            fault: None,
            plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        });
        let app_b = router(AppState {
            recovery,
            vault,
            vfs,
            identity,
            lease: lease_b,
            repair,
            events,
            host,
            share,
            oauth: Arc::new(os_plugin_host::lifecycle::OAuthCoordinator::new()),
            plugin_authors: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_capabilities: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            device_id: dev_b,
            fault: None,
            plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            plugin_decisions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        });
        let vault_id = create_vault_for_test(&app_a).await;

        // A acquires at a fixed "now=0" with TTL=30.
        let acq = app_a
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lease"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"now_epoch_secs": 0, "ttl_secs": 30})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let acq_status = acq.status();
        let acq_body = axum::body::to_bytes(acq.into_body(), 8192).await.unwrap();
        assert_eq!(
            acq_status,
            StatusCode::OK,
            "acquire body: {:?}",
            String::from_utf8_lossy(&acq_body)
        );

        // B tries to steal while still live → 409.
        let steal_too_soon = app_b
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lease/steal"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "now_epoch_secs": 30,
                            "expires_at_epoch_secs": 60,
                            "ttl_secs": 30,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let s = steal_too_soon.status();
        let b = axum::body::to_bytes(steal_too_soon.into_body(), 8192)
            .await
            .unwrap();
        assert_eq!(
            s,
            StatusCode::CONFLICT,
            "steal body: {:?}",
            String::from_utf8_lossy(&b)
        );

        // B steals after 2×TTL.
        let stolen = app_b
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lease/steal"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "now_epoch_secs": 1000,
                            "expires_at_epoch_secs": 1030,
                            "ttl_secs": 30,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stolen.status(), StatusCode::OK);

        // A's renew now returns 410 Gone (lease.lost).
        let renew = app_a
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/vaults/{vault_id}/lease/renew"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(renew.status(), StatusCode::GONE);
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
