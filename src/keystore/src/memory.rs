//! In-memory keystore for tests and development.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::{Keystore, KeystoreError, Secret};

#[derive(Default)]
pub struct MemoryKeystore {
    inner: Mutex<HashMap<String, [u8; 32]>>,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keystore for MemoryKeystore {
    fn store(&self, key_id: &str, secret: &[u8; 32]) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .expect("keystore mutex poisoned")
            .insert(key_id.to_string(), *secret);
        Ok(())
    }

    fn load(&self, key_id: &str) -> Result<Secret, KeystoreError> {
        let g = self.inner.lock().expect("keystore mutex poisoned");
        match g.get(key_id) {
            Some(b) => Ok(Zeroizing::new(*b)),
            None => Err(KeystoreError::NotFound(key_id.to_string())),
        }
    }

    fn delete(&self, key_id: &str) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .expect("keystore mutex poisoned")
            .remove(key_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let k = MemoryKeystore::new();
        k.store("a", &[7u8; 32]).unwrap();
        let s = k.load("a").unwrap();
        assert_eq!(*s, [7u8; 32]);
    }

    #[test]
    fn delete_removes() {
        let k = MemoryKeystore::new();
        k.store("a", &[1u8; 32]).unwrap();
        k.delete("a").unwrap();
        assert!(matches!(k.load("a"), Err(KeystoreError::NotFound(_))));
    }
}
