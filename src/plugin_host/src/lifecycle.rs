//! Plugin lifecycle helpers — F-PL-1 install (TOFU), F-PL-2 OAuth state
//! machine, F-PL-3 capability drift diff.
//!
//! These primitives are pure data + crypto; the durable state (registered
//! authors, OAuth sessions in flight, plugin states) lives in the calling
//! engine, which threads them through the API surface.

use std::collections::HashMap;
use std::sync::Mutex;

use os_crypto::{verify, CryptoError};
use os_types::{
    AeadNonce, AeadSuite, AeadTag, CapabilitySet, CredentialsHandle, Ed25519Pub, Ed25519Sig,
    KeyPurpose, LegalClass, PluginId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("manifest signature invalid")]
    SignatureInvalid,
    #[error("author key has rotated since last install — re-confirmation required")]
    AuthorRotated,
    #[error("red legal class requires double-confirmation")]
    RedLegalClassUnconfirmed,
    #[error("oauth session not found")]
    OAuthSessionNotFound,
    #[error("oauth scope mismatch: required {required:?} missing in {received:?}")]
    OAuthInsufficientScope {
        required: Vec<String>,
        received: Vec<String>,
    },
    #[error("crypto: {0:?}")]
    Crypto(CryptoError),
}

impl From<CryptoError> for LifecycleError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

// ─── F-PL-1 manifest ──────────────────────────────────────────────────────

/// Manifest accompanying a plugin artifact. All fields except the
/// signature are part of the canonical signed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: PluginId,
    pub version: String,
    pub author_pubkey: Ed25519Pub,
    pub legal_class: LegalClass,
    pub requested_capabilities: CapabilitySet,
    pub source_url: String,
    pub signature: Ed25519Sig,
}

/// Decision the user must explicitly make on install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserConfirmation {
    /// User has clicked "install".
    Confirm,
    /// For red `legal_class`, the user has clicked the *second* confirm
    /// after seeing the warning. Plain `Confirm` is rejected for red.
    DoubleConfirm,
}

/// Verify a plugin manifest. Returns `Ok` if the install is allowed to
/// proceed, `Err` otherwise. The caller persists the (plugin_id →
/// author_pubkey) mapping after a successful first install so subsequent
/// installs can detect TOFU rotation.
pub fn verify_install(
    manifest: &PluginManifest,
    prior_known_author: Option<&Ed25519Pub>,
    confirmation: UserConfirmation,
) -> Result<(), LifecycleError> {
    let canon = canonical_manifest_bytes(manifest)?;
    verify(&manifest.author_pubkey, &canon, &manifest.signature)
        .map_err(|_| LifecycleError::SignatureInvalid)?;
    if let Some(prior) = prior_known_author {
        if prior != &manifest.author_pubkey {
            return Err(LifecycleError::AuthorRotated);
        }
    }
    if matches!(manifest.legal_class, LegalClass::Red) {
        if !matches!(confirmation, UserConfirmation::DoubleConfirm) {
            return Err(LifecycleError::RedLegalClassUnconfirmed);
        }
    }
    Ok(())
}

fn canonical_manifest_bytes(m: &PluginManifest) -> Result<Vec<u8>, LifecycleError> {
    let mut clone = m.clone();
    clone.signature = Ed25519Sig([0u8; 64]);
    let mut out = Vec::new();
    ciborium::into_writer(&clone, &mut out).map_err(|_| LifecycleError::Crypto(CryptoError::Input("encode")))?;
    Ok(out)
}

// ─── F-PL-2 OAuth ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthSession {
    pub plugin_id: PluginId,
    pub state: String,
    pub auth_url: String,
    pub required_scopes: Vec<String>,
}

/// In-process coordinator for outstanding OAuth flows. Tests and the API
/// share one of these so a `start` followed by a `complete` round-trip
/// produces a wrapped credential.
///
/// Per spec, `CredentialsHandle` is a small opaque ID; the actual wrapped
/// token bytes live in a side store. The coordinator persists them in
/// `wrapped_credentials` keyed by the handle bytes; production builds
/// route this through `os-keystore`.
pub struct OAuthCoordinator {
    sessions: Mutex<HashMap<String, OAuthSession>>,
    wrapped_credentials: Mutex<HashMap<Vec<u8>, WrappedToken>>,
}

impl OAuthCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            wrapped_credentials: Mutex::new(HashMap::new()),
        }
    }

    /// Start a new OAuth session. The provider's authorization URL and a
    /// random `state` are returned to the frontend, which redirects the
    /// user. The frontend then calls `complete` with the code and state.
    pub fn start(
        &self,
        plugin_id: PluginId,
        auth_url: String,
        required_scopes: Vec<String>,
    ) -> OAuthSession {
        use rand::RngCore;
        let mut state_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut state_bytes);
        let state = state_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let session = OAuthSession {
            plugin_id,
            state,
            auth_url,
            required_scopes,
        };
        self.sessions
            .lock()
            .expect("oauth sessions")
            .insert(session.state.clone(), session.clone());
        session
    }

    /// Complete an OAuth flow. The caller has already exchanged the
    /// authorization code for a token; we wrap that token under the
    /// vault's MK using the `kp:cred-wrap` purpose and return a
    /// `CredentialsHandle` plus the pruned-from-cache state.
    ///
    /// `granted_scopes` must be a superset of the session's
    /// `required_scopes`; otherwise the install is refused per spec edge
    /// case "Provider returns insufficient scope".
    pub fn complete(
        &self,
        state: &str,
        token: &[u8],
        granted_scopes: &[String],
        master_key: &os_crypto::SymKey,
    ) -> Result<(OAuthSession, CredentialsHandle), LifecycleError> {
        let session = self
            .sessions
            .lock()
            .expect("oauth sessions")
            .remove(state)
            .ok_or(LifecycleError::OAuthSessionNotFound)?;
        for required in &session.required_scopes {
            if !granted_scopes.iter().any(|s| s == required) {
                return Err(LifecycleError::OAuthInsufficientScope {
                    required: session.required_scopes.clone(),
                    received: granted_scopes.to_vec(),
                });
            }
        }
        let wrap_key =
            os_crypto::derive_subkey(master_key, KeyPurpose::CRED_WRAP, Some(session.plugin_id.0.as_bytes()))?;
        let nonce = os_crypto::random_nonce_12();
        let aad = format!("oauth:{}", session.plugin_id.0);
        let (ct, tag) = os_crypto::encrypt(
            AeadSuite::ChaCha20Poly1305,
            &wrap_key,
            &nonce,
            token,
            aad.as_bytes(),
        )?;
        let wrapped = WrappedToken {
            plugin_id: session.plugin_id.clone(),
            ciphertext: ct,
            nonce,
            tag,
        };
        // Spec: CredentialsHandle is a small opaque pointer (≤ 64 bytes).
        // We mint a fresh UUID-shaped handle and stash the actual
        // wrapped token under the same bytes in the coordinator's
        // side-store.
        use rand::RngCore;
        let mut handle_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut handle_bytes);
        let cred = CredentialsHandle::new(handle_bytes.to_vec())
            .map_err(|_| LifecycleError::Crypto(CryptoError::Input("handle")))?;
        self.wrapped_credentials
            .lock()
            .expect("oauth wrapped")
            .insert(handle_bytes.to_vec(), wrapped);
        Ok((session, cred))
    }

    /// Look up a previously wrapped token. Returns `None` if the handle
    /// isn't recognized.
    pub fn unwrap(
        &self,
        handle: &CredentialsHandle,
        master_key: &os_crypto::SymKey,
    ) -> Result<Option<Vec<u8>>, LifecycleError> {
        let wrapped = self
            .wrapped_credentials
            .lock()
            .expect("oauth wrapped")
            .get(handle.as_bytes())
            .cloned();
        let wrapped = match wrapped {
            Some(w) => w,
            None => return Ok(None),
        };
        let wrap_key = os_crypto::derive_subkey(
            master_key,
            KeyPurpose::CRED_WRAP,
            Some(wrapped.plugin_id.0.as_bytes()),
        )?;
        let aad = format!("oauth:{}", wrapped.plugin_id.0);
        let pt = os_crypto::decrypt(
            AeadSuite::ChaCha20Poly1305,
            &wrap_key,
            &wrapped.nonce,
            &wrapped.ciphertext,
            &wrapped.tag,
            aad.as_bytes(),
        )?;
        Ok(Some(pt))
    }

    pub fn cancel(&self, state: &str) -> Result<(), LifecycleError> {
        self.sessions
            .lock()
            .expect("oauth sessions")
            .remove(state)
            .ok_or(LifecycleError::OAuthSessionNotFound)?;
        Ok(())
    }

    pub fn pending_count(&self) -> usize {
        self.sessions.lock().expect("oauth sessions").len()
    }
}

impl Default for OAuthCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedToken {
    plugin_id: PluginId,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
    nonce: AeadNonce,
    tag: AeadTag,
}


// ─── F-PL-3 capability drift ──────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityDiff {
    pub gained: Vec<String>,
    pub lost: Vec<String>,
}

impl CapabilityDiff {
    pub fn is_empty(&self) -> bool {
        self.gained.is_empty() && self.lost.is_empty()
    }
}

/// Compute the (gained, lost) flag deltas between the prior and current
/// capability sets. Used by the engine on plugin reload to decide whether
/// to transition to `AwaitingUserDecision`.
pub fn diff_capabilities(prev: &CapabilitySet, current: &CapabilitySet) -> CapabilityDiff {
    let mut gained = Vec::new();
    let mut lost = Vec::new();
    for c in &current.flags {
        if !prev.flags.contains(c) {
            gained.push(format!("{:?}", c));
        }
    }
    for c in &prev.flags {
        if !current.flags.contains(c) {
            lost.push(format!("{:?}", c));
        }
    }
    CapabilityDiff { gained, lost }
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_crypto::{generate_keypair, sign, SymKey};
    use os_types::Capability;
    use rand::rngs::OsRng;

    fn manifest(legal: LegalClass, sk: &os_types::Ed25519Priv, pk: Ed25519Pub) -> PluginManifest {
        let mut m = PluginManifest {
            plugin_id: PluginId::new("org.test.plugin"),
            version: "1.0.0".into(),
            author_pubkey: pk,
            legal_class: legal,
            requested_capabilities: CapabilitySet::default(),
            source_url: "https://example.com/p.wasm".into(),
            signature: Ed25519Sig([0u8; 64]),
        };
        let canon = canonical_manifest_bytes(&m).unwrap();
        m.signature = sign(sk, &canon);
        m
    }

    /// F-PL-1 — happy path: signature verifies, no prior author, green
    /// legal class accepts plain Confirm.
    #[test]
    fn install_signature_round_trip() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let m = manifest(LegalClass::Green, &sk, pk);
        verify_install(&m, None, UserConfirmation::Confirm).unwrap();
    }

    /// F-PL-1 — TOFU continuity: prior author key must match.
    #[test]
    fn install_rejects_rotated_author() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let m = manifest(LegalClass::Green, &sk, pk);
        let (_other_sk, other_pk) = generate_keypair(&mut OsRng);
        let err = verify_install(&m, Some(&other_pk), UserConfirmation::Confirm);
        assert!(matches!(err, Err(LifecycleError::AuthorRotated)));
    }

    /// F-PL-1 — red legal class needs DoubleConfirm.
    #[test]
    fn install_red_legal_requires_double_confirm() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let m = manifest(LegalClass::Red, &sk, pk);
        assert!(matches!(
            verify_install(&m, None, UserConfirmation::Confirm),
            Err(LifecycleError::RedLegalClassUnconfirmed)
        ));
        verify_install(&m, None, UserConfirmation::DoubleConfirm).unwrap();
    }

    /// F-PL-1 — tampered manifest rejected.
    #[test]
    fn install_rejects_tampered_signature() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let mut m = manifest(LegalClass::Green, &sk, pk);
        m.version = "9.9.9".into();
        let err = verify_install(&m, None, UserConfirmation::Confirm);
        assert!(matches!(err, Err(LifecycleError::SignatureInvalid)));
    }

    /// F-PL-2 — start/complete round trip wraps the token under MK and
    /// the unwrap recovers the original bytes.
    #[test]
    fn oauth_round_trip_wraps_token() {
        let coord = OAuthCoordinator::new();
        let pid = PluginId::new("org.test.oauth");
        let session = coord.start(
            pid.clone(),
            "https://provider/auth?state=xxx".into(),
            vec!["files.write".into()],
        );
        let mk = SymKey::from_bytes([5u8; 32]);
        let (_s, cred) = coord
            .complete(
                &session.state,
                b"raw-access-token",
                &["files.write".into(), "files.read".into()],
                &mk,
            )
            .unwrap();
        assert_eq!(coord.pending_count(), 0);
        let recovered = coord.unwrap(&cred, &mk).unwrap().unwrap();
        assert_eq!(recovered, b"raw-access-token");
    }

    /// F-PL-2 — refusing a session with insufficient scope.
    #[test]
    fn oauth_insufficient_scope_rejected() {
        let coord = OAuthCoordinator::new();
        let pid = PluginId::new("org.test.oauth");
        let session = coord.start(pid, "url".into(), vec!["needs.write".into()]);
        let mk = SymKey::from_bytes([5u8; 32]);
        let err = coord.complete(&session.state, b"tok", &["only.read".into()], &mk);
        assert!(matches!(
            err,
            Err(LifecycleError::OAuthInsufficientScope { .. })
        ));
    }

    /// F-PL-2 — cancel removes the pending session.
    #[test]
    fn oauth_cancel() {
        let coord = OAuthCoordinator::new();
        let pid = PluginId::new("org.test.oauth");
        let s = coord.start(pid, "url".into(), vec![]);
        coord.cancel(&s.state).unwrap();
        assert_eq!(coord.pending_count(), 0);
    }

    /// F-PL-3 — capability diff identifies gained and lost flags.
    #[test]
    fn capability_diff_detects_drift() {
        let prev = CapabilitySet::default()
            .with(Capability::RangeRead)
            .with(Capability::Tombstone);
        let current = CapabilitySet::default()
            .with(Capability::RangeRead)
            .with(Capability::QuotaReport);
        let d = diff_capabilities(&prev, &current);
        assert_eq!(d.gained.len(), 1);
        assert_eq!(d.lost.len(), 1);
        assert!(d.gained.contains(&"QuotaReport".into()));
        assert!(d.lost.contains(&"Tombstone".into()));
    }

    /// F-PL-3 — equal sets produce an empty diff.
    #[test]
    fn capability_diff_empty_when_unchanged() {
        let prev = CapabilitySet::default().with(Capability::RangeRead);
        let current = prev.clone();
        let d = diff_capabilities(&prev, &current);
        assert!(d.is_empty());
    }
}
