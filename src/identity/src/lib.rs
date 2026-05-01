//! os-identity — owner identity chain (Ed25519 sign keys + ML-KEM key wraps)
//! plus peer management.
//!
//! The identity chain is the authoritative trust root. Every share is signed
//! by the *current* epoch's sign key; recipient verification walks the chain.

#![forbid(unsafe_code)]

use std::sync::Arc;

use os_crypto::{blake3_160, generate_keypair, sign, verify};
use os_entities::{Identity, IdentityEpoch, Peer};
use os_metadata::{MetadataError, Store, Txn};
use os_types::{
    BlakeHash, Ed25519Priv, Ed25519Pub, Ed25519Sig, EpochId, IdentityId, MlKemPub, PeerId,
    Timestamp,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity not found: {0}")]
    NotFound(String),
    #[error("chain validation failed at epoch {0}")]
    ChainInvalid(u32),
    #[error("anchor mismatch")]
    AnchorMismatch,
    #[error("peer chain outdated; have epoch {have}, signed at {signed_at}")]
    PeerChainOutdated { have: u32, signed_at: u32 },
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("metadata: {0}")]
    Metadata(String),
}

impl From<MetadataError> for IdentityError {
    fn from(e: MetadataError) -> Self {
        Self::Metadata(e.to_string())
    }
}

pub struct IdentityService {
    store: Arc<Store>,
}

impl IdentityService {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// Create a fresh epoch_0 identity. Returns the in-memory `Identity` plus
    /// the signing private key for the current epoch.
    pub fn create_identity(
        &self,
        timestamp: Timestamp,
    ) -> Result<(Identity, Ed25519Priv), IdentityError> {
        use rand::rngs::OsRng;
        let (sign_priv, sign_pub) = generate_keypair(&mut OsRng);
        let kem_pub = placeholder_kem_pub();
        let fp = fingerprint_of(&sign_pub);
        let identity_id = id_string_for(&fp);
        let epoch = IdentityEpoch {
            epoch: EpochId::ZERO,
            sign_pubkey: sign_pub,
            kem_pubkey: kem_pub,
            fingerprint: fp,
            created_at: timestamp,
            wrapped_privkeys: Vec::new(),
            signed_by_prev: None,
        };
        let id = Identity {
            identity_id,
            epochs: vec![epoch],
        };
        let mut txn = Txn::new();
        self.store.put_identity(&mut txn, &id)?;
        self.store.commit(txn)?;
        Ok((id, sign_priv))
    }

    pub fn rotate_identity(
        &self,
        identity_id: &IdentityId,
        prev_priv: &Ed25519Priv,
        timestamp: Timestamp,
    ) -> Result<(IdentityEpoch, Ed25519Priv), IdentityError> {
        use rand::rngs::OsRng;
        let mut id = self
            .store
            .get_identity(identity_id)?
            .ok_or_else(|| IdentityError::NotFound(identity_id.0.clone()))?;
        let prev = id.epochs.last().expect("identity has epoch_0").clone();
        let next_epoch = prev.epoch.next();
        let (new_priv, new_pub) = generate_keypair(&mut OsRng);
        let kem_pub = placeholder_kem_pub();
        let fp = fingerprint_of(&new_pub);
        let to_sign = chain_signing_message(next_epoch, &new_pub, &kem_pub);
        let sig = sign(prev_priv, &to_sign);
        let epoch = IdentityEpoch {
            epoch: next_epoch,
            sign_pubkey: new_pub,
            kem_pubkey: kem_pub,
            fingerprint: fp,
            created_at: timestamp,
            wrapped_privkeys: Vec::new(),
            signed_by_prev: Some(sig),
        };
        id.epochs.push(epoch.clone());
        let mut txn = Txn::new();
        self.store.put_identity(&mut txn, &id)?;
        self.store.commit(txn)?;
        Ok((epoch, new_priv))
    }

    /// Verify the chain forward from epoch 0. Anchor fingerprint must match
    /// `expected_anchor`.
    pub fn verify_chain(
        chain: &[IdentityEpoch],
        expected_anchor: BlakeHash,
    ) -> Result<(), IdentityError> {
        if chain.is_empty() {
            return Err(IdentityError::ChainInvalid(0));
        }
        if chain[0].fingerprint != expected_anchor {
            return Err(IdentityError::AnchorMismatch);
        }
        for window in chain.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            let to_sign = chain_signing_message(next.epoch, &next.sign_pubkey, &next.kem_pubkey);
            let sig = next
                .signed_by_prev
                .as_ref()
                .ok_or(IdentityError::ChainInvalid(next.epoch.0))?;
            verify(&prev.sign_pubkey, &to_sign, sig)
                .map_err(|_| IdentityError::ChainInvalid(next.epoch.0))?;
        }
        Ok(())
    }

    pub fn add_peer(&self, peer: Peer) -> Result<(), IdentityError> {
        let mut txn = Txn::new();
        self.store.put_peer(&mut txn, &peer)?;
        self.store.commit(txn)?;
        Ok(())
    }

    pub fn verify_peer_signature(
        &self,
        peer_id: &PeerId,
        signed_at: EpochId,
        message: &[u8],
        sig: &Ed25519Sig,
    ) -> Result<(), IdentityError> {
        let peer = self
            .store
            .get_peer(peer_id)?
            .ok_or_else(|| IdentityError::NotFound(peer_id.0.clone()))?;
        if signed_at.0 > peer.last_seen_epoch.0 {
            return Err(IdentityError::PeerChainOutdated {
                have: peer.last_seen_epoch.0,
                signed_at: signed_at.0,
            });
        }
        let epoch = peer
            .epochs
            .iter()
            .find(|e| e.epoch == signed_at)
            .ok_or(IdentityError::ChainInvalid(signed_at.0))?;
        verify(&epoch.sign_pubkey, message, sig).map_err(|_| IdentityError::SignatureInvalid)
    }
}

fn chain_signing_message(epoch: EpochId, sign_pub: &Ed25519Pub, kem_pub: &MlKemPub) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 32 + kem_pub.0.len());
    v.extend_from_slice(&epoch.0.to_be_bytes());
    v.extend_from_slice(&sign_pub.0);
    v.extend_from_slice(&kem_pub.0);
    v
}

pub fn fingerprint_of(pubkey: &Ed25519Pub) -> BlakeHash {
    let fp20 = blake3_160(&pubkey.0);
    let mut full = [0u8; 32];
    full[..20].copy_from_slice(&fp20);
    BlakeHash::from_bytes(full)
}

pub fn id_string_for(fp: &BlakeHash) -> IdentityId {
    let bytes = &fp.as_bytes()[..20];
    IdentityId(format!(
        "id:{}",
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, bytes).to_lowercase()
    ))
}

pub fn peer_id_for(pubkey: &Ed25519Pub) -> PeerId {
    let fp = blake3_160(&pubkey.0);
    PeerId(format!(
        "peer:{}",
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &fp).to_lowercase()
    ))
}

fn placeholder_kem_pub() -> MlKemPub {
    use rand::RngCore;
    let mut b = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    MlKemPub(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_metadata::backend::MemoryBackend;

    fn store() -> Arc<Store> {
        Arc::new(Store::new(Arc::new(MemoryBackend::new())))
    }

    #[test]
    fn create_then_verify_chain() {
        let svc = IdentityService::new(store());
        let (id, sk) = svc.create_identity(Timestamp::from_string("now")).unwrap();
        let anchor = id.epochs[0].fingerprint;
        IdentityService::verify_chain(&id.epochs, anchor).unwrap();
        let (e1, sk2) = svc
            .rotate_identity(&id.identity_id, &sk, Timestamp::from_string("t2"))
            .unwrap();
        let _ = svc
            .rotate_identity(&id.identity_id, &sk2, Timestamp::from_string("t3"))
            .unwrap();
        let id = svc.store.get_identity(&id.identity_id).unwrap().unwrap();
        IdentityService::verify_chain(&id.epochs, anchor).unwrap();
        assert_eq!(id.epochs.len(), 3);
        assert_eq!(id.epochs[1].epoch, e1.epoch);
    }

    #[test]
    fn anchor_mismatch_rejected() {
        let svc = IdentityService::new(store());
        let (id, _sk) = svc.create_identity(Timestamp::from_string("now")).unwrap();
        let bogus = BlakeHash::from_bytes([0xff; 32]);
        assert!(matches!(
            IdentityService::verify_chain(&id.epochs, bogus),
            Err(IdentityError::AnchorMismatch)
        ));
    }

    #[test]
    fn peer_signature_verifies() {
        use rand::rngs::OsRng;
        let svc = IdentityService::new(store());
        let (peer_priv, peer_pub) = generate_keypair(&mut OsRng);
        let pid = peer_id_for(&peer_pub);
        let epoch0 = IdentityEpoch {
            epoch: EpochId::ZERO,
            sign_pubkey: peer_pub,
            kem_pubkey: placeholder_kem_pub(),
            fingerprint: fingerprint_of(&peer_pub),
            created_at: Timestamp::from_string("t"),
            wrapped_privkeys: Vec::new(),
            signed_by_prev: None,
        };
        let peer = Peer {
            peer_id: pid.clone(),
            epochs: vec![epoch0],
            label: "alice".into(),
            verified: true,
            last_seen_epoch: EpochId::ZERO,
            added_at: Timestamp::from_string("t"),
        };
        svc.add_peer(peer).unwrap();
        let sig = sign(&peer_priv, b"hello");
        assert!(svc
            .verify_peer_signature(&pid, EpochId::ZERO, b"hello", &sig)
            .is_ok());
    }
}
