//! OS keyring-backed keystore. Uses the `keyring` crate which adapts to:
//! macOS Keychain, Windows Credential Manager, libsecret on Linux, etc.
//!
//! Secrets are stored hex-encoded under service `"openstorage"` with the
//! caller-supplied `key_id` as the entry name.

use keyring::Entry;
use zeroize::Zeroizing;

use crate::{Keystore, KeystoreError, Secret};

const SERVICE: &str = "openstorage";

pub struct SystemKeystore {
    service: String,
}

impl SystemKeystore {
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_string(),
        }
    }
    pub fn with_service(s: impl Into<String>) -> Self {
        Self { service: s.into() }
    }
}

impl Default for SystemKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Keystore for SystemKeystore {
    fn store(&self, key_id: &str, secret: &[u8; 32]) -> Result<(), KeystoreError> {
        let entry = Entry::new(&self.service, key_id)
            .map_err(|e| KeystoreError::Platform(e.to_string()))?;
        entry
            .set_password(&hex::encode(secret))
            .map_err(|e| KeystoreError::Platform(e.to_string()))
    }

    fn load(&self, key_id: &str) -> Result<Secret, KeystoreError> {
        let entry = Entry::new(&self.service, key_id)
            .map_err(|e| KeystoreError::Platform(e.to_string()))?;
        match entry.get_password() {
            Ok(s) => {
                let bytes = hex::decode(&s).map_err(|_| KeystoreError::Length {
                    expected: 32,
                    got: s.len() / 2,
                })?;
                if bytes.len() != 32 {
                    return Err(KeystoreError::Length {
                        expected: 32,
                        got: bytes.len(),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Zeroizing::new(arr))
            }
            Err(keyring::Error::NoEntry) => Err(KeystoreError::NotFound(key_id.to_string())),
            Err(e) => Err(KeystoreError::Platform(e.to_string())),
        }
    }

    fn delete(&self, key_id: &str) -> Result<(), KeystoreError> {
        let entry = Entry::new(&self.service, key_id)
            .map_err(|e| KeystoreError::Platform(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeystoreError::Platform(e.to_string())),
        }
    }
}
