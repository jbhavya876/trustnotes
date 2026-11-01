#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Hybrid digital signatures (Ed25519 + ML-DSA-65).
//!
//! Enforces:
//! - Mandatory AND verification: both classical (Ed25519) and post-quantum (ML-DSA-65) signatures MUST verify.
//! - Failure of either scheme immediately emits `TnError::BadSignature`.
//! - No signature scheme may ever be skipped or downgraded.

use ed25519_dalek::{Signer as EdSigner, Verifier as EdVerifier};
use ml_dsa::signature::{Signer as PqSigner, Verifier as PqVerifier};
use ml_dsa::{EncodedVerifyingKey, KeyExport, MlDsa65, VerifyingKey as PqVerifyingKey};
use serde::{Deserialize, Serialize};
use tn_types::TnError;
use zeroize::Zeroize;

/// Hybrid digital signature containing both classical (Ed25519) and PQ (ML-DSA-65) signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// 64-byte Ed25519 signature.
    #[serde(with = "tn_types::serde_bytes_64")]
    pub ed25519: [u8; 64],
    /// Serialized ML-DSA-65 signature (3309 bytes).
    pub ml_dsa: Vec<u8>,
}

/// Device or Account private signing keys.
pub struct SigningKeys {
    ed_key: ed25519_dalek::SigningKey,
    pq_key: ml_dsa::SigningKey<MlDsa65>,
}

impl SigningKeys {
    /// Generates fresh random signing keys using OS CSPRNG.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if OS entropy generation fails.
    pub fn generate() -> Result<Self, TnError> {
        let mut ed_seed = [0u8; 32];
        let mut pq_seed = [0u8; 32];
        getrandom::getrandom(&mut ed_seed)
            .map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;
        getrandom::getrandom(&mut pq_seed)
            .map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;

        let keys = Self::from_seeds(&ed_seed, &pq_seed);
        ed_seed.zeroize();
        pq_seed.zeroize();
        Ok(keys)
    }

    /// Derives signing keys deterministically from 32-byte seeds.
    #[must_use]
    pub fn from_seeds(ed_seed: &[u8; 32], pq_seed: &[u8; 32]) -> Self {
        let ed_key = ed25519_dalek::SigningKey::from_bytes(ed_seed);
        let pq_seed_array: &ml_dsa::B32 = pq_seed.into();
        let pq_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(pq_seed_array);

        Self { ed_key, pq_key }
    }

    /// Returns the public verifying keys corresponding to these signing keys.
    #[must_use]
    pub fn verifying_keys(&self) -> VerifyingKeys {
        let ed_vk = self.ed_key.verifying_key();
        let pq_vk: &PqVerifyingKey<MlDsa65> = self.pq_key.as_ref();
        let pq_vk_bytes = pq_vk.to_bytes();

        VerifyingKeys {
            ed25519_bytes: ed_vk.to_bytes(),
            mldsa65_bytes: pq_vk_bytes.as_slice().to_vec(),
        }
    }

    /// Computes hybrid signature over `message` using both Ed25519 and ML-DSA-65.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let ed_sig = self.ed_key.sign(message);
        let pq_sig = self.pq_key.sign(message);
        let pq_sig_bytes = pq_sig.encode();

        HybridSignature {
            ed25519: ed_sig.to_bytes(),
            ml_dsa: pq_sig_bytes.as_slice().to_vec(),
        }
    }
}

impl Drop for SigningKeys {
    fn drop(&mut self) {
        // Zeroization handled automatically by inner dalek/ml_dsa types
    }
}

/// Device or Account public verifying keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyingKeys {
    /// 32-byte Ed25519 public key.
    pub ed25519_bytes: [u8; 32],
    /// Serialized ML-DSA-65 public key (1952 bytes).
    pub mldsa65_bytes: Vec<u8>,
}

impl VerifyingKeys {
    /// Create `VerifyingKeys` from raw bytes.
    #[must_use]
    pub const fn from_parts(ed25519: [u8; 32], mldsa65: Vec<u8>) -> Self {
        Self {
            ed25519_bytes: ed25519,
            mldsa65_bytes: mldsa65,
        }
    }

    /// Verifies that BOTH Ed25519 and ML-DSA-65 signatures are valid.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` if either signature check fails.
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> Result<(), TnError> {
        // 1. Verify classical Ed25519 signature
        let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519_bytes)
            .map_err(|_| TnError::BadSignature)?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);

        ed_vk
            .verify(message, &ed_sig)
            .map_err(|_| TnError::BadSignature)?;

        // 2. Verify post-quantum ML-DSA-65 signature
        let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(self.mldsa65_bytes.as_slice())
            .map_err(|_| TnError::BadSignature)?;
        let pq_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc_vk);

        let pq_sig_parsed = ml_dsa::Signature::<MlDsa65>::try_from(sig.ml_dsa.as_slice())
            .map_err(|_| TnError::BadSignature)?;

        pq_vk
            .verify(message, &pq_sig_parsed)
            .map_err(|_| TnError::BadSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_and_verify_happy_path() {
        let keys = SigningKeys::generate().unwrap();
        let vk = keys.verifying_keys();
        let message = b"TrustNotes verified mutation payload";

        let sig = keys.sign(message);
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_verify_ed25519_tampered_fails() {
        let keys = SigningKeys::generate().unwrap();
        let vk = keys.verifying_keys();
        let message = b"TrustNotes verified mutation payload";

        let mut sig = keys.sign(message);
        sig.ed25519[0] ^= 0xFF; // Corrupt Ed25519 signature

        let res = vk.verify(message, &sig);
        assert!(matches!(res, Err(TnError::BadSignature)));
    }

    #[test]
    fn test_hybrid_verify_mldsa_tampered_fails() {
        let keys = SigningKeys::generate().unwrap();
        let vk = keys.verifying_keys();
        let message = b"TrustNotes verified mutation payload";

        let mut sig = keys.sign(message);
        let last = sig.ml_dsa.len() - 1;
        sig.ml_dsa[last] ^= 0xFF; // Corrupt ML-DSA-65 signature

        let res = vk.verify(message, &sig);
        assert!(matches!(res, Err(TnError::BadSignature)));
    }

    #[test]
    fn test_hybrid_verify_wrong_message_fails() {
        let keys = SigningKeys::generate().unwrap();
        let vk = keys.verifying_keys();
        let sig = keys.sign(b"Original message");

        let res = vk.verify(b"Altered message", &sig);
        assert!(matches!(res, Err(TnError::BadSignature)));
    }
}
