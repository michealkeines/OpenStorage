//! Plugin host: registry of `ProviderId → Arc<dyn PluginContract>`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use os_types::ProviderId;

use crate::contract::{PluginContract, VaultPluginContract};
use crate::{PluginError, Result};

pub struct Host {
    chunk_plugins: RwLock<HashMap<ProviderId, Arc<dyn PluginContract>>>,
    vault_plugins: RwLock<HashMap<ProviderId, Arc<dyn VaultPluginContract>>>,
}

impl Host {
    pub fn new() -> Self {
        Self {
            chunk_plugins: RwLock::new(HashMap::new()),
            vault_plugins: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_chunk(&self, id: ProviderId, plugin: Arc<dyn PluginContract>) {
        self.chunk_plugins
            .write()
            .expect("host registry")
            .insert(id, plugin);
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
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("chunk plugin {id}")))
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
