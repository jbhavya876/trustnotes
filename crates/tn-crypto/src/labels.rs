#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Context label registry and domain separation invariants.
//!
//! Every cryptographic operation (hash, KDF, signature, AEAD associated data)
//! carries a unique, versioned context label prefixed with `tn/v1/`.
//!
//! A test fails if a label is used for two purposes or built dynamically from untrusted input.

/// Label for deriving Account Root from Recovery Key.
pub const LABEL_ACCOUNT_ROOT: &str = "tn/v1/account-root";

/// Label for deriving Account Identity Key (Ed25519 seed).
pub const LABEL_IDENTITY_ED25519: &str = "tn/v1/identity-ed25519";

/// Label for deriving Account Identity Key (ML-DSA-65 seed).
pub const LABEL_IDENTITY_MLDSA65: &str = "tn/v1/identity-mldsa65";

/// Label for deriving Vault Key from Account Root.
pub const LABEL_VAULT_KEY: &str = "tn/v1/vault-key";

/// Prefix for computing `account_id` from identity public keys.
pub const LABEL_ACCOUNT_ID: &str = "tn/v1/account-id";

/// Associated data label for wrapping Note Keys under Vault Key.
pub const LABEL_NK_WRAP: &str = "tn/v1/nk-wrap";

/// Prefix for deriving unique `op_id` from `OpHeader`.
pub const LABEL_OP_ID: &str = "tn/v1/op-id";

/// Signature context label for operations.
pub const LABEL_SIG_OP: &str = "tn/v1/sig/op";

/// AEAD associated data label for note payload encryption.
pub const LABEL_AEAD_OP: &str = "tn/v1/aead/op";

/// Prefix for epoch tree leaf hashes.
pub const LABEL_EPOCH_LEAF: &str = "tn/v1/epoch-leaf";

/// Signature label for server receipts.
pub const LABEL_RECEIPT_SIG: &str = "tn/v1/receipt/sig";

/// Signature label for device certificates.
pub const LABEL_DEVICE_CERT: &str = "tn/v1/device/cert";

/// Info label for HPKE device enrollment packages.
pub const LABEL_DEVICE_ENROLLMENT: &str = "tn/v1/device/enrollment";

/// Signature label for device gossip checkpoints.
pub const LABEL_GOSSIP_SIG: &str = "tn/v1/gossip/sig";

/// Label for evidence bundles.
pub const LABEL_EVIDENCE_BUNDLE: &str = "tn/v1/evidence/bundle";

/// Label for release log leaves.
pub const LABEL_RELEASE_LEAF: &str = "tn/v1/release-leaf";

/// Signature label for reproducible build builder attestations.
pub const LABEL_BUILDER_SIG: &str = "tn/v1/builder/sig";

/// Domain separation label for account key rotation cross-signatures.
pub const LABEL_KEY_ROTATE: &str = "tn/v1/key-rotate";

/// Comprehensive slice of all defined context labels.
pub const ALL_LABELS: &[&str] = &[
    LABEL_ACCOUNT_ROOT,
    LABEL_IDENTITY_ED25519,
    LABEL_IDENTITY_MLDSA65,
    LABEL_VAULT_KEY,
    LABEL_ACCOUNT_ID,
    LABEL_NK_WRAP,
    LABEL_OP_ID,
    LABEL_SIG_OP,
    LABEL_AEAD_OP,
    LABEL_EPOCH_LEAF,
    LABEL_RECEIPT_SIG,
    LABEL_DEVICE_CERT,
    LABEL_DEVICE_ENROLLMENT,
    LABEL_GOSSIP_SIG,
    LABEL_EVIDENCE_BUNDLE,
    LABEL_RELEASE_LEAF,
    LABEL_BUILDER_SIG,
    LABEL_KEY_ROTATE,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn labels_are_unique() {
        let mut seen = HashSet::new();
        for label in ALL_LABELS {
            assert!(
                seen.insert(*label),
                "duplicate context label detected: {label}"
            );
        }
        assert_eq!(ALL_LABELS.len(), 18);
    }

    #[test]
    fn labels_have_correct_prefix() {
        for label in ALL_LABELS {
            assert!(
                label.starts_with("tn/v1/"),
                "context label does not start with tn/v1/: {label}"
            );
        }
    }
}
