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

use os_recovery::RecoveryService;
use os_types::VaultId;
use os_vault::VaultManager;
use os_vfs::VfsService;

#[derive(Clone)]
pub struct AppState {
    pub recovery: Arc<RecoveryService>,
    pub vault: Arc<VaultManager>,
    pub vfs: Arc<VfsService>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/system/status", get(system_status))
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/:vault_id/unlock", post(unlock_vault))
        .route("/v1/vaults/:vault_id/lock", post(lock_vault))
        .route(
            "/v1/vaults/:vault_id/files/*path",
            get(get_file)
                .put(put_file)
                .head(head_file)
                .delete(delete_file),
        )
        .route("/v1/vaults/:vault_id/dirs", get(list_dir))
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

async fn delete_file(
    State(s): State<AppState>,
    Path((_vault_id, path)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let path = format!("/{path}");
    s.vfs
        .delete(&path)
        .map_err(|e| ApiError::not_found(format!("delete: {e}")))?;
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
        let vault = Arc::new(VaultManager::new(store.clone(), host));
        let mut tdir = std::env::temp_dir();
        tdir.push(format!("os-api-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tdir).unwrap();
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(tdir.join("wal.bin"))
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
        let recovery = Arc::new(RecoveryService::new(store.clone(), identity, vault.clone()));
        let vfs = Arc::new(VfsService::new(store, vault.clone(), sync));
        router(AppState {
            recovery,
            vault,
            vfs,
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
