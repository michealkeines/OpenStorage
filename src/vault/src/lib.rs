//! os-vault — vault state machine, vault-provider replication, snapshot.
//!
//! Holds the in-memory `VaultState` (Locked/Unlocking/Unlocked/etc.), the
//! master key while unlocked, and the live `VaultBinding` for this device.

#![forbid(unsafe_code)]

use std::sync::{Arc, RwLock};

use os_crypto::SymKey;
use os_entities::{Provider, VaultBinding};
use os_metadata::Store;
use os_placement::PoolSnapshot;
use os_plugin_host::Host;
use os_types::{ProviderId, VaultId};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is in {0:?}; operation not allowed")]
    BadState(VaultState),
    #[error("vault {0} unknown")]
    Unknown(VaultId),
    #[error("metadata: {0}")]
    Metadata(String),
}

impl From<os_metadata::MetadataError> for VaultError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Uncreated,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    Destroying,
    Destroyed,
}

pub struct VaultManager {
    store: Arc<Store>,
    plugin_host: Arc<Host>,
    inner: RwLock<VaultManagerInner>,
}

struct VaultManagerInner {
    vault_id: Option<VaultId>,
    state: VaultState,
    mk: Option<Zeroizing<[u8; 32]>>,
    binding: Option<VaultBinding>,
}

impl VaultManager {
    pub fn new(store: Arc<Store>, plugin_host: Arc<Host>) -> Self {
        Self {
            store,
            plugin_host,
            inner: RwLock::new(VaultManagerInner {
                vault_id: None,
                state: VaultState::Uncreated,
                mk: None,
                binding: None,
            }),
        }
    }

    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    pub fn plugin_host(&self) -> Arc<Host> {
        self.plugin_host.clone()
    }

    pub fn state(&self) -> VaultState {
        self.inner.read().expect("vault mgr").state
    }

    pub fn vault_id(&self) -> Option<VaultId> {
        self.inner.read().expect("vault mgr").vault_id
    }

    pub fn current_pool(&self) -> Result<PoolSnapshot, VaultError> {
        let providers: Vec<Provider> = self.store.iter_providers()?;
        Ok(PoolSnapshot::from_providers(&providers))
    }

    pub fn list_chunk_providers(&self) -> Vec<ProviderId> {
        self.plugin_host.list_chunk()
    }

    pub fn set_unlocked(&self, vault_id: VaultId, mk: [u8; 32]) -> Result<(), VaultError> {
        let mut g = self.inner.write().expect("vault mgr");
        g.vault_id = Some(vault_id);
        g.state = VaultState::Unlocked;
        g.mk = Some(Zeroizing::new(mk));
        Ok(())
    }

    pub fn set_binding(&self, b: VaultBinding) {
        self.inner.write().expect("vault mgr").binding = Some(b);
    }

    pub fn binding(&self) -> Option<VaultBinding> {
        self.inner.read().expect("vault mgr").binding.clone()
    }

    pub fn master_key(&self) -> Option<SymKey> {
        let g = self.inner.read().expect("vault mgr");
        g.mk.as_ref().map(|m| SymKey::from_bytes(**m))
    }

    pub fn lock(&self) -> Result<(), VaultError> {
        let mut g = self.inner.write().expect("vault mgr");
        if g.state != VaultState::Unlocked {
            return Err(VaultError::BadState(g.state));
        }
        g.state = VaultState::Locking;
        g.mk = None;
        g.state = VaultState::Locked;
        Ok(())
    }

    /// Replace the in-memory MK with `new_mk`. Used by `rotate_master_key`
    /// after the recovery service has re-wrapped the manifest.
    pub fn replace_mk(&self, new_mk: [u8; 32]) -> Result<(), VaultError> {
        let mut g = self.inner.write().expect("vault mgr");
        if g.state != VaultState::Unlocked {
            return Err(VaultError::BadState(g.state));
        }
        g.mk = Some(Zeroizing::new(new_mk));
        Ok(())
    }

    /// Drive Unlocked → Destroying → Destroyed. Caller is responsible for
    /// the residual sweep through the plugin host before calling this; we
    /// just transition the state machine and zeroize the master key.
    pub fn begin_destroying(&self) -> Result<(), VaultError> {
        let mut g = self.inner.write().expect("vault mgr");
        match g.state {
            VaultState::Unlocked | VaultState::Locked => {
                g.state = VaultState::Destroying;
                g.mk = None;
                Ok(())
            }
            other => Err(VaultError::BadState(other)),
        }
    }

    pub fn finish_destroying(&self) -> Result<(), VaultError> {
        let mut g = self.inner.write().expect("vault mgr");
        if g.state != VaultState::Destroying {
            return Err(VaultError::BadState(g.state));
        }
        g.state = VaultState::Destroyed;
        g.vault_id = None;
        g.binding = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_metadata::backend::MemoryBackend;

    #[test]
    fn lock_zeroizes_mk() {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let host = Arc::new(Host::new());
        let vm = VaultManager::new(store, host);
        vm.set_unlocked(VaultId::new_v7(), [42u8; 32]).unwrap();
        assert!(vm.master_key().is_some());
        vm.lock().unwrap();
        assert_eq!(vm.state(), VaultState::Locked);
        assert!(vm.master_key().is_none());
    }
}
