//! os-share — per-recipient key wraps and revocation.
//!
//! Skeleton implementation. Full sharing flow (KEM encapsulate, share blob
//! signing, revocation cascade) lands when multi-peer scenarios are wired.

#![forbid(unsafe_code)]

use std::sync::Arc;

use os_entities::Share;
use os_metadata::{Store, Txn};
use os_types::{ShareId, Timestamp};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("not found: {0}")]
    NotFound(ShareId),
    #[error("metadata: {0}")]
    Metadata(String),
    #[error("not implemented: {0}")]
    Unimplemented(&'static str),
}

impl From<os_metadata::MetadataError> for ShareError {
    fn from(e: os_metadata::MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}

pub struct ShareService {
    store: Arc<Store>,
}

impl ShareService {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn create_share(&self, share: Share) -> Result<ShareId, ShareError> {
        let id = share.share_id;
        let mut txn = Txn::new();
        self.store.put_share(&mut txn, &share)?;
        self.store.commit(txn)?;
        Ok(id)
    }

    pub fn get_share(&self, id: ShareId) -> Result<Option<Share>, ShareError> {
        Ok(self.store.get_share(id)?)
    }

    pub fn revoke_share(&self, id: ShareId, now: Timestamp) -> Result<(), ShareError> {
        let mut share = self.store.get_share(id)?.ok_or(ShareError::NotFound(id))?;
        share.revoked_at = Some(now);
        let mut txn = Txn::new();
        self.store.put_share(&mut txn, &share)?;
        self.store.commit(txn)?;
        Ok(())
    }
}
