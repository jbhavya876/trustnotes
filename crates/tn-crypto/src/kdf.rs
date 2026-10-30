#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Key derivation functions using HKDF-SHA-256 and Argon2id.
//!
//! Enforces exact domain separation per `docs/CRYPTO.md`.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tn_types::{Id32, TnError};

use crate::keys::{AccountRoot, LocalStorageKey, RecoveryKey, VaultKey};
use crate::labels::{
    LABEL_ACCOUNT_ID, LABEL_ACCOUNT_ROOT, LABEL_IDENTITY_ED25519, LABEL_IDENTITY_MLDSA65,
    LABEL_VAULT_KEY,
};

/// Derives the Account Root (AR) from the 256-bit Recovery Key (RK).
///
/// # Panics
/// Panics only if HKDF expansion fails (which cannot occur for 32-byte OKM).
#[must_use]
pub fn derive_account_root(rk: &RecoveryKey) -> AccountRoot {
    let hk = Hkdf::<Sha256>::new(None, rk.expose_bytes());
    let mut okm = [0u8; 32];
    hk.expand(LABEL_ACCOUNT_ROOT.as_bytes(), &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    AccountRoot::from_bytes(okm)
}

/// Derives the 32-byte seed for Account Identity Key (Ed25519) from AR.
///
/// # Panics
/// Panics only if HKDF expansion fails.
#[must_use]
pub fn derive_aik_ed_seed(ar: &AccountRoot) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ar.expose_bytes());
    let mut okm = [0u8; 32];
    hk.expand(LABEL_IDENTITY_ED25519.as_bytes(), &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

/// Derives the 32-byte seed for Account Identity Key (ML-DSA-65) from AR.
///
/// # Panics
/// Panics only if HKDF expansion fails.
#[must_use]
pub fn derive_aik_pq_seed(ar: &AccountRoot) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ar.expose_bytes());
    let mut okm = [0u8; 32];
    hk.expand(LABEL_IDENTITY_MLDSA65.as_bytes(), &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

/// Derives the Vault Key (VK) from AR.
///
/// # Panics
/// Panics only if HKDF expansion fails.
#[must_use]
pub fn derive_vault_key(ar: &AccountRoot) -> VaultKey {
    let hk = Hkdf::<Sha256>::new(None, ar.expose_bytes());
    let mut okm = [0u8; 32];
    hk.expand(LABEL_VAULT_KEY.as_bytes(), &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    VaultKey::from_bytes(okm)
}

/// Computes `account_id` from identity public keys: SHA-256("tn/v1/account-id" || `ed_pk` || `pq_pk`).
#[must_use]
pub fn derive_account_id(ed_pk: &[u8; 32], pq_pk: &[u8]) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_ACCOUNT_ID.as_bytes());
    hasher.update(ed_pk);
    hasher.update(pq_pk);
    let hash: [u8; 32] = hasher.finalize().into();
    Id32::from_bytes(hash)
}

/// Derives a Local Storage Key (LSK) from a passphrase and 16-byte salt using Argon2id.
///
/// Argon2id parameters:
/// - Memory: 64 MiB (65,536 KiB)
/// - Iterations: 3
/// - Parallelism: 4
/// - Output: 32 bytes
///
/// # Errors
/// Returns `TnError::Internal` if password hashing fails.
pub fn derive_lsk_from_passphrase(
    passphrase: &str,
    salt: &[u8; 16],
) -> Result<LocalStorageKey, TnError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| TnError::Internal(format!("Invalid Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| TnError::Internal(format!("Argon2id derivation failed: {e}")))?;

    Ok(LocalStorageKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_deterministic() {
        let rk = RecoveryKey::from_bytes([42u8; 32]);
        let ar1 = derive_account_root(&rk);
        let ar2 = derive_account_root(&rk);
        assert_eq!(ar1.expose_bytes(), ar2.expose_bytes());

        let vk1 = derive_vault_key(&ar1);
        let vk2 = derive_vault_key(&ar2);
        assert_eq!(vk1.expose_bytes(), vk2.expose_bytes());

        assert_ne!(ar1.expose_bytes(), vk1.expose_bytes());
    }

    #[test]
    fn test_argon2id_derivation() {
        let salt = [0x55u8; 16];
        let lsk1 = derive_lsk_from_passphrase("correct-horse-battery-staple", &salt).unwrap();
        let lsk2 = derive_lsk_from_passphrase("correct-horse-battery-staple", &salt).unwrap();
        assert_eq!(lsk1.expose_bytes(), lsk2.expose_bytes());

        let lsk3 = derive_lsk_from_passphrase("different-passphrase", &salt).unwrap();
        assert_ne!(lsk1.expose_bytes(), lsk3.expose_bytes());
    }
}
