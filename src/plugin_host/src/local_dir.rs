//! `LocalDirPlugin` — reference filesystem-backed plugin for local-only and
//! development workflows. Stores each object as a file under `root/`. The
//! `NativeHandle` is the file's name (random hex from `OsRng`).
//!
//! Implements both `PluginContract` (chunk role) and `VaultPluginContract`
//! (vault-metadata role). CAS is implemented by reading the current etag,
//! comparing, then writing a temp file + rename atomically.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_types::{
    AeadTag, BlakeHash, CachedElsewhereRisk, DeleteOutcome, HealthScore, LatencyProfile,
    PriorHandleState, QuotaReclaimed, QuotaState, Range, RateLimitState, Timestamp,
};

use crate::contract::{
    CasOutcome, CasResult, DeleteResult, HealthReport, HealthState, ListEntry, PeekResult,
    PluginContract, PutResult, VaultPluginContract,
};
use crate::{PluginError, Result};

pub struct LocalDirPlugin {
    root: PathBuf,
    /// Coarse mutex around mutating ops to keep CAS sane. A real backend would
    /// use atomic operations on the underlying store.
    lock: Mutex<()>,
}

impl LocalDirPlugin {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| PluginError::Io(e.to_string()))?;
        Ok(Self {
            root,
            lock: Mutex::new(()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn handle_to_path(&self, h: &NativeHandle) -> PathBuf {
        self.root.join(hex::encode(&h.0))
    }

    fn name_to_path(&self, name: &str) -> PathBuf {
        // Names may contain `/` (e.g. `lease/<vault>` or `wal/<dev>/<seq>`)
        // which we don't want to interpret as filesystem path segments.
        // Replace with a sentinel that's unlikely to appear in an
        // identifier but trivially round-trippable.
        let flat = name.replace('/', "%2F");
        self.root.join(format!("name:{flat}"))
    }

    fn fresh_handle() -> NativeHandle {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        NativeHandle(b.to_vec())
    }

    fn etag_of(bytes: &[u8]) -> BlakeHash {
        os_crypto::blake3_32(bytes)
    }

    fn ts_now() -> Timestamp {
        Timestamp::from_string(time_now_iso())
    }
}

fn time_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

#[async_trait]
impl PluginContract for LocalDirPlugin {
    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult> {
        let _g = self.lock.lock().expect("plugin mutex");
        let handle = Self::fresh_handle();
        let path = self.handle_to_path(&handle);
        std::fs::write(&path, payload).map_err(|e| PluginError::Io(e.to_string()))?;
        let prior = match &hint.replaces_handle {
            Some(prev) => {
                let prev_path = self.handle_to_path(prev);
                if prev_path.exists() {
                    let _ = std::fs::remove_file(&prev_path);
                    Some(PriorHandleState::Removed)
                } else {
                    Some(PriorHandleState::Unknown)
                }
            }
            None => None,
        };
        Ok(PutResult {
            handle,
            handle_changed: true,
            prior_handle_state: prior,
            stored_at: Self::ts_now(),
            quota_reclaimed: QuotaReclaimed::Unknown,
            tombstone_clears_at: None,
        })
    }

    async fn get(&self, handle: &NativeHandle, range: Option<Range>) -> Result<Vec<u8>> {
        let path = self.handle_to_path(handle);
        let bytes = std::fs::read(&path).map_err(|e| PluginError::Io(e.to_string()))?;
        match range {
            Some(r) => {
                let start = (r.start as usize).min(bytes.len());
                let end = (r.end as usize).min(bytes.len());
                Ok(bytes[start..end].to_vec())
            }
            None => Ok(bytes),
        }
    }

    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult> {
        let path = self.handle_to_path(handle);
        match std::fs::metadata(&path) {
            Ok(md) => Ok(PeekResult {
                exists: true,
                size: md.len(),
                mtime: Self::ts_now(),
                etag: None,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PeekResult {
                exists: false,
                size: 0,
                mtime: Self::ts_now(),
                etag: None,
            }),
            Err(e) => Err(PluginError::Io(e.to_string())),
        }
    }

    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult> {
        let _g = self.lock.lock().expect("plugin mutex");
        let path = self.handle_to_path(handle);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(DeleteResult {
                outcome: DeleteOutcome::Removed,
                quota_reclaimed: QuotaReclaimed::Yes,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeleteResult {
                outcome: DeleteOutcome::NotFound,
                quota_reclaimed: QuotaReclaimed::No,
                cached_elsewhere_risk: CachedElsewhereRisk::Low,
                tombstone_clears_at: None,
            }),
            Err(e) => Err(PluginError::Io(e.to_string())),
        }
    }

    async fn health(&self) -> Result<HealthReport> {
        Ok(HealthReport {
            state: HealthState::Healthy,
            quota: QuotaState {
                total: None,
                used: None,
                untrusted: false,
            },
            rate_limit: RateLimitState {
                remaining: u32::MAX,
                reset_at: Self::ts_now(),
            },
            latency: LatencyProfile::default(),
            score: HealthScore::new(1.0),
        })
    }
}

#[async_trait]
impl VaultPluginContract for LocalDirPlugin {
    async fn list(
        &self,
        prefix: &str,
        limit: u32,
        cursor: Option<Vec<u8>>,
    ) -> Result<(Vec<ListEntry>, Option<Vec<u8>>)> {
        // The on-disk name encoding flattens `/` ⇒ `%2F` (see
        // `name_to_path`). Apply the same transform to the prefix so
        // listings match nested-name slots like `wal/<dev>/<seq>`.
        let flat_prefix = prefix.replace('/', "%2F");
        let prefix_full = format!("name:{flat_prefix}");
        let mut entries = Vec::new();
        let start_cursor = cursor.and_then(|c| String::from_utf8(c).ok()).unwrap_or_default();
        let mut iter = std::fs::read_dir(&self.root).map_err(|e| PluginError::Io(e.to_string()))?;
        let mut names: Vec<String> = Vec::new();
        while let Some(entry) = iter.next() {
            let entry = entry.map_err(|e| PluginError::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix_full) {
                names.push(name);
            }
        }
        names.sort();
        let next_cursor = None;
        for n in names.into_iter().filter(|n| n.as_str() > start_cursor.as_str()).take(limit as usize)
        {
            // Reverse the flattening so callers see the original logical
            // name (e.g. `wal/<dev>/<seq>`).
            let bare_flat = n.strip_prefix("name:").unwrap_or(&n).to_string();
            let bare = bare_flat.replace("%2F", "/");
            let path = self.root.join(&n);
            let md = std::fs::metadata(&path).map_err(|e| PluginError::Io(e.to_string()))?;
            let bytes = std::fs::read(&path).map_err(|e| PluginError::Io(e.to_string()))?;
            entries.push(ListEntry {
                name: bare,
                size: md.len(),
                etag: Some(Self::etag_of(&bytes)),
                mtime: Self::ts_now(),
            });
        }
        Ok((entries, next_cursor))
    }

    async fn cas_write(
        &self,
        name: &str,
        payload: &[u8],
        expected_etag: Option<BlakeHash>,
    ) -> Result<CasResult> {
        let _g = self.lock.lock().expect("plugin mutex");
        let path = self.name_to_path(name);
        let current_etag = match std::fs::read(&path) {
            Ok(b) => Some(Self::etag_of(&b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(PluginError::Io(e.to_string())),
        };
        if expected_etag != current_etag {
            return Ok(CasResult {
                outcome: CasOutcome::EtagMismatch,
                new_etag: current_etag,
            });
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, payload).map_err(|e| PluginError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| PluginError::Io(e.to_string()))?;
        Ok(CasResult {
            outcome: CasOutcome::Written,
            new_etag: Some(Self::etag_of(payload)),
        })
    }

    async fn named_get(&self, name: &str) -> Result<Option<(Vec<u8>, BlakeHash)>> {
        let _g = self.lock.lock().expect("plugin mutex");
        let path = self.name_to_path(name);
        match std::fs::read(&path) {
            Ok(b) => {
                let etag = Self::etag_of(&b);
                Ok(Some((b, etag)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PluginError::Io(e.to_string())),
        }
    }
}

// Hint that we expect callers to track tags separately; we don't store them.
#[allow(dead_code)]
fn _bind_aead_tag_type(_: AeadTag) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("os-plugin-host-test-{}", uuid::Uuid::now_v7()));
        p
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let p = LocalDirPlugin::new(tempdir()).unwrap();
        let r = p.put(b"hello", &PutHint::default()).await.unwrap();
        let bytes = p.get(&r.handle, None).await.unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn delete_returns_removed() {
        let p = LocalDirPlugin::new(tempdir()).unwrap();
        let r = p.put(b"x", &PutHint::default()).await.unwrap();
        let dr = p.delete(&r.handle).await.unwrap();
        assert_eq!(dr.outcome, DeleteOutcome::Removed);
    }

    #[tokio::test]
    async fn cas_write_first_succeeds_then_fails() {
        let p = LocalDirPlugin::new(tempdir()).unwrap();
        let first = p.cas_write("k", b"v1", None).await.unwrap();
        assert_eq!(first.outcome, CasOutcome::Written);
        let stale = p.cas_write("k", b"v2", None).await.unwrap();
        assert_eq!(stale.outcome, CasOutcome::EtagMismatch);
        let cur = first.new_etag;
        let ok = p.cas_write("k", b"v2", cur).await.unwrap();
        assert_eq!(ok.outcome, CasOutcome::Written);
    }
}
