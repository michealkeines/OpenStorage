//! Plugin host: registry of `ProviderId → plugin instance + middleware`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use os_types::ProviderId;

use crate::contract::{PluginContract, VaultPluginContract};
use crate::rate_limit::{MiddlewarePolicy, RateLimitConfig, RateLimitMiddleware};
use crate::{PluginError, Result};

pub struct Host {
    chunk_plugins: RwLock<HashMap<ProviderId, ChunkEntry>>,
    vault_plugins: RwLock<HashMap<ProviderId, Arc<dyn VaultPluginContract>>>,
}

#[derive(Clone)]
struct ChunkEntry {
    /// What callers see — already wrapped in middleware when registered
    /// through `register_chunk_paced`.
    plugin: Arc<dyn PluginContract>,
    /// Concrete handle on the middleware so the dispatcher can read
    /// per-provider capacity / cooldown without paying a downcast.
    middleware: Option<Arc<RateLimitMiddleware>>,
}

impl Host {
    pub fn new() -> Self {
        Self {
            chunk_plugins: RwLock::new(HashMap::new()),
            vault_plugins: RwLock::new(HashMap::new()),
        }
    }

    /// Register a chunk plugin. The host calls `plugin.rate_limit_profile()`
    /// to learn the backend's limits, then wraps the plugin in
    /// `RateLimitMiddleware` automatically. Plugin authors don't have to
    /// know anything about middleware — they just declare their profile.
    pub fn register_chunk(&self, id: ProviderId, plugin: Arc<dyn PluginContract>) {
        self.register_chunk_with_policy(id, plugin, MiddlewarePolicy::default());
    }

    /// Same as `register_chunk` but with an explicit host policy override
    /// (max-transient-attempts, backoff bounds, jitter).
    pub fn register_chunk_with_policy(
        &self,
        id: ProviderId,
        plugin: Arc<dyn PluginContract>,
        policy: MiddlewarePolicy,
    ) {
        let profile = plugin.rate_limit_profile();
        let cfg = RateLimitConfig::from_profile(&profile, &policy);
        let label = format!("chunk:{}:{}", profile.label, id);
        let mw = Arc::new(RateLimitMiddleware::new(plugin, cfg).with_label(label));
        let wrapped: Arc<dyn PluginContract> = mw.clone();
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin: wrapped,
                middleware: Some(mw),
            },
        );
    }

    /// Register without any pacing. Test fixtures only — production paths
    /// always go through `register_chunk` so profiles are honored.
    pub fn register_chunk_unpaced(&self, id: ProviderId, plugin: Arc<dyn PluginContract>) {
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin,
                middleware: None,
            },
        );
    }

    /// Register with a hand-crafted `RateLimitConfig`, bypassing the
    /// plugin's profile. Test fixtures only — for production, the plugin's
    /// `rate_limit_profile()` is the source of truth.
    pub fn register_chunk_with_config(
        &self,
        id: ProviderId,
        plugin: Arc<dyn PluginContract>,
        cfg: RateLimitConfig,
    ) {
        let mw = Arc::new(
            RateLimitMiddleware::new(plugin, cfg).with_label(format!("chunk:{id}")),
        );
        let wrapped: Arc<dyn PluginContract> = mw.clone();
        self.chunk_plugins.write().expect("host registry").insert(
            id,
            ChunkEntry {
                plugin: wrapped,
                middleware: Some(mw),
            },
        );
    }

    pub fn register_vault(&self, id: ProviderId, plugin: Arc<dyn VaultPluginContract>) {
        self.vault_plugins
            .write()
            .expect("host registry")
            .insert(id, plugin);
    }

    pub fn get_chunk(&self, id: ProviderId) -> Result<Arc<dyn PluginContract>> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .map(|e| e.plugin.clone())
            .ok_or_else(|| PluginError::NotFound(format!("chunk plugin {id}")))
    }

    /// Returns the middleware wrapping `id`, if any. The dispatcher uses
    /// this to query capacity without locking the bucket from outside.
    pub fn middleware_for(&self, id: ProviderId) -> Option<Arc<RateLimitMiddleware>> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .and_then(|e| e.middleware.clone())
    }

    pub fn get_vault(&self, id: ProviderId) -> Result<Arc<dyn VaultPluginContract>> {
        self.vault_plugins
            .read()
            .expect("host registry")
            .get(&id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("vault plugin {id}")))
    }

    pub fn list_chunk(&self) -> Vec<ProviderId> {
        self.chunk_plugins
            .read()
            .expect("host registry")
            .keys()
            .copied()
            .collect()
    }

    pub fn list_vault(&self) -> Vec<ProviderId> {
        self.vault_plugins
            .read()
            .expect("host registry")
            .keys()
            .copied()
            .collect()
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}
