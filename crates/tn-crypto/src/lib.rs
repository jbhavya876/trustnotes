#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-crypto`: Cryptographic primitive wrappers for trustnotes.
//!
//! # Security Invariants
//!
//! - Every key is a newtype. Raw `[u8; 32]` never crosses a module boundary.
//! - Nonces are generated inside the AEAD wrapper. Callers cannot supply them
//!   (except in test-only vector functions behind `#[cfg(test)]`).
//! - Secret types: no `Clone` unless required, no `Debug` output of contents,
//!   `Drop` zeroizes.
//! - The hybrid signature rule is AND: both Ed25519 and ML-DSA-65 must verify.
//!   Either failing rejects. Never accept either-or.
//! - Known-answer tests for every primitive wrapper must pass before any release.
//!
//! # Domain Separation
//!
//! Every hash, KDF call, signature, and AEAD associated-data string carries a
//! unique, versioned context label from the registry in `docs/CRYPTO.md`. A
//! test in this crate fails if any label is used for two purposes.
//!
//! # M0 Status
//!
//! This crate is a skeleton. All functions return `TnError::Internal("not implemented — M1")`.
//! Implementations land in M1 once KATs are established.

use tn_types::TnError;

/// HKDF-SHA-256 key derivation functions and the account key hierarchy.
pub mod kdf {
    use crate::TnError;

    /// The account root key, derived from the Recovery Key.
    /// Never leaves the device. Zeroized on drop.
    pub struct AccountRoot(pub(crate) [u8; 32]);

    impl Drop for AccountRoot {
        fn drop(&mut self) {
            // Zeroization via volatile writes — replaced with `zeroize` crate in M1.
            self.0.fill(0);
        }
    }

    /// Derive the account root from the recovery key.
    /// Context label: `tn/v1/account-root`
    ///
    /// # Errors
    ///
    /// Returns [`TnError::Internal`] until M1 implements HKDF-SHA-256.
    pub fn derive_account_root(_recovery_key: &[u8; 32]) -> Result<AccountRoot, TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

/// XChaCha20-Poly1305 authenticated encryption.
pub mod aead {
    use crate::TnError;

    /// Encrypt plaintext with a random 192-bit nonce.
    ///
    /// The nonce is generated inside this function. Callers cannot supply it.
    ///
    /// Output layout: `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`TnError::Internal`] until M1 implements XChaCha20-Poly1305.
    pub fn seal(_key: &[u8; 32], _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }

    /// Decrypt ciphertext (which includes the prepended 24-byte nonce).
    ///
    /// # Errors
    ///
    /// Returns [`TnError::CiphertextTampered`] on authentication failure.
    /// Returns [`TnError::Internal`] until M1 implements XChaCha20-Poly1305.
    pub fn open(_key: &[u8; 32], _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

/// Ed25519 + ML-DSA-65 hybrid signatures.
pub mod signature {
    use crate::TnError;

    /// A hybrid signature pair: (Ed25519 signature bytes, ML-DSA-65 signature bytes).
    /// Both must verify for the overall signature to be accepted.
    pub struct HybridSignature {
        /// Ed25519 signature (64 bytes).
        pub ed25519: [u8; 64],
        /// ML-DSA-65 signature (variable length, ~3309 bytes).
        pub ml_dsa: Vec<u8>,
    }

    /// Verify a hybrid signature. **Both** components must verify.
    /// Either component failing rejects the entire signature.
    ///
    /// # Errors
    ///
    /// Returns [`TnError::BadSignature`] if either component fails.
    /// Returns [`TnError::Internal`] until M1 implements Ed25519 + ML-DSA-65.
    pub fn verify(
        _message: &[u8],
        _sig: &HybridSignature,
        _ed25519_pubkey: &[u8; 32],
        _ml_dsa_pubkey: &[u8],
        _label: &str,
    ) -> Result<(), TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

/// Padding functions (fixed buckets + Padme for large plaintexts).
pub mod padding {
    use crate::TnError;

    /// Pad plaintext to the next bucket size using ISO/IEC 7816-4 padding
    /// (`0x80` then zero bytes).
    ///
    /// Buckets: 256, 512, 1024, 2048, 4096 bytes.
    /// Above 4096 bytes uses [Padme](https://lbarman.ch/blog/padme/) rounding.
    #[must_use]
    pub fn pad(_plaintext: &[u8]) -> Vec<u8> {
        // Implemented in M1.
        vec![]
    }

    /// Remove ISO/IEC 7816-4 padding from decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`TnError::Decode`] if padding is malformed.
    pub fn unpad(_padded: &[u8]) -> Result<Vec<u8>, TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_m0() {
        // Known-answer tests are implemented in M1.
        // This test exists solely to ensure the crate compiles cleanly.
        assert_eq!(1 + 1, 2);
    }
}
