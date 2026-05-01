//! Op-size and indirection-eligibility policy.

use os_entities::{KeyKind, Op};

use crate::WalError;

/// Default 64 KB.
pub const DEFAULT_MAX_ENTRY_BYTES: usize = 64 * 1024;

/// Configuration knobs for the WAL.
#[derive(Debug, Clone, Copy)]
pub struct WalConfig {
    pub max_entry_bytes: usize,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
        }
    }
}

/// `(KeyKind, field)` pairs that MUST NOT be stored as `LwwRegisterIndirect`.
/// See ABSTRACTIONS §7 indirect-eligibility policy (AD-1).
pub const FORBIDDEN_INDIRECT_FIELDS: &[(KeyKind, &str)] = &[
    (KeyKind::File, "wrapped_keys"),
    (KeyKind::Vault, "identity_chain"),
    (KeyKind::Vault, "allowed_devices"),
    (KeyKind::Vault, "snapshot_pointer"),
    // RecoveryManifest.* — any field
    // LeaseRecord.* — any field
    // Both of those are stored as singleton blobs, not as op targets, so they
    // can't appear here under our schema. The check is duplicated in the
    // higher layers that mint ops for those entities.
];

pub fn check_indirect_allowed(op: &Op) -> Result<(), WalError> {
    if let Op::LwwRegisterIndirect { target, .. } = op {
        for (k, f) in FORBIDDEN_INDIRECT_FIELDS {
            if &target.kind == k && target.field == *f {
                return Err(WalError::IndirectionForbidden(*k, target.field.clone()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_entities::Key;
    use os_types::{BlakeHash, LocalKvKey};

    #[test]
    fn forbidden_field_rejected() {
        let op = Op::LwwRegisterIndirect {
            target: Key::new(KeyKind::Vault, vec![0u8; 16], "identity_chain"),
            value_hash: BlakeHash::from_bytes([0u8; 32]),
            value_storage_key: LocalKvKey::new(vec![1, 2, 3]),
            value_size_bytes: 100_000,
            previous_value_hash: None,
        };
        assert!(matches!(
            check_indirect_allowed(&op),
            Err(WalError::IndirectionForbidden(_, _))
        ));
    }

    #[test]
    fn ordinary_field_allowed() {
        let op = Op::LwwRegisterIndirect {
            target: Key::new(KeyKind::File, vec![0u8; 16], "content_type"),
            value_hash: BlakeHash::from_bytes([0u8; 32]),
            value_storage_key: LocalKvKey::new(vec![1, 2, 3]),
            value_size_bytes: 100_000,
            previous_value_hash: None,
        };
        assert!(check_indirect_allowed(&op).is_ok());
    }
}
