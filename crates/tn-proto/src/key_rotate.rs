#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Account key rotation transition payloads and cross-signatures (`OpKind::KeyRotate = 5`, ADR-0002).
//!
//! Enforces:
//! - Mandatory dual cross-signing by both retiring AIK and newly active AIK.
//! - Atomically transitions account verifying keys on the sequencer and clients.
//! - Cryptographic defense against operator-side account takeover (Claim C1, C3).

use serde::{Deserialize, Serialize};
use tn_crypto::labels::LABEL_KEY_ROTATE;
use tn_crypto::{HybridSignature, SigningKeys, VerifyingKeys};
use tn_types::{cbor, Id32, TnError};

#[derive(Debug, Serialize, Deserialize)]
struct KeyRotateEnvelope<'a> {
    account_id: Id32,
    new_aik_ed_pub: [u8; 32],
    new_aik_pq_pub: &'a [u8],
    rotated_at: u64,
}

/// Signed key rotation payload embedded in a `KeyRotate` (kind 5) operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotatePayload {
    /// Schema version (1).
    pub v: u32,
    /// Associated account identifier.
    pub account_id: Id32,
    /// New classical Ed25519 identity key.
    pub new_aik_ed_pub: [u8; 32],
    /// New post-quantum ML-DSA-65 identity key.
    pub new_aik_pq_pub: Vec<u8>,
    /// Timestamp when key rotation was executed (Unix ms).
    pub rotated_at: u64,
    /// Cross-signature authored by retiring AIK.
    pub old_aik_sig: HybridSignature,
    /// Cross-signature authored by newly generated AIK.
    pub new_aik_sig: HybridSignature,
}

impl KeyRotatePayload {
    /// Authors a dual cross-signed key rotation transition payload.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if serialization fails.
    pub fn create(
        account_id: Id32,
        new_aik_keys: &SigningKeys,
        old_aik_keys: &SigningKeys,
        rotated_at: u64,
    ) -> Result<Self, TnError> {
        let new_vk = new_aik_keys.verifying_keys();

        let env = KeyRotateEnvelope {
            account_id,
            new_aik_ed_pub: new_vk.ed25519_bytes,
            new_aik_pq_pub: &new_vk.mldsa65_bytes,
            rotated_at,
        };
        let env_cbor = cbor::encode_canonical(&env)?;

        let mut msg = Vec::with_capacity(LABEL_KEY_ROTATE.len() + env_cbor.len());
        msg.extend_from_slice(LABEL_KEY_ROTATE.as_bytes());
        msg.extend_from_slice(&env_cbor);

        // Sign with both old and new AIKs
        let old_aik_sig = old_aik_keys.sign(&msg);
        let new_aik_sig = new_aik_keys.sign(&msg);

        Ok(Self {
            v: 1,
            account_id,
            new_aik_ed_pub: new_vk.ed25519_bytes,
            new_aik_pq_pub: new_vk.mldsa65_bytes,
            rotated_at,
            old_aik_sig,
            new_aik_sig,
        })
    }

    /// Verifies that both cross-signatures are valid.
    ///
    /// # Returns
    /// The newly authenticated `VerifyingKeys` upon successful validation.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` if either signature fails to verify.
    pub fn verify(&self, old_aik_vk: &VerifyingKeys) -> Result<VerifyingKeys, TnError> {
        let new_vk = VerifyingKeys {
            ed25519_bytes: self.new_aik_ed_pub,
            mldsa65_bytes: self.new_aik_pq_pub.clone(),
        };

        let env = KeyRotateEnvelope {
            account_id: self.account_id,
            new_aik_ed_pub: self.new_aik_ed_pub,
            new_aik_pq_pub: &self.new_aik_pq_pub,
            rotated_at: self.rotated_at,
        };
        let env_cbor = cbor::encode_canonical(&env)?;

        let mut msg = Vec::with_capacity(LABEL_KEY_ROTATE.len() + env_cbor.len());
        msg.extend_from_slice(LABEL_KEY_ROTATE.as_bytes());
        msg.extend_from_slice(&env_cbor);

        // 1. Verify retiring AIK signature
        old_aik_vk.verify(&msg, &self.old_aik_sig)?;

        // 2. Verify new AIK signature
        new_vk.verify(&msg, &self.new_aik_sig)?;

        Ok(new_vk)
    }

    /// Serializes payload to canonical CBOR.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on error.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Deserializes payload from canonical CBOR.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on error.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_rotate_payload_roundtrip_and_verify() {
        let account_id = Id32::from_bytes([0x77; 32]);
        let now_ms = 1_700_000_000_000u64;

        let old_aik = SigningKeys::generate().unwrap();
        let new_aik = SigningKeys::generate().unwrap();

        let payload = KeyRotatePayload::create(account_id, &new_aik, &old_aik, now_ms).unwrap();

        let cbor_bytes = payload.to_cbor().unwrap();
        let decoded = KeyRotatePayload::from_cbor(&cbor_bytes).unwrap();
        assert_eq!(payload, decoded);

        // Verify with old AIK VK -> returns new AIK VK
        let verified_new_vk = decoded.verify(&old_aik.verifying_keys()).unwrap();
        assert_eq!(verified_new_vk, new_aik.verifying_keys());
    }

    #[test]
    fn test_key_rotate_tampered_fails() {
        let account_id = Id32::from_bytes([0x77; 32]);
        let now_ms = 1_700_000_000_000u64;

        let old_aik = SigningKeys::generate().unwrap();
        let new_aik = SigningKeys::generate().unwrap();

        let mut payload = KeyRotatePayload::create(account_id, &new_aik, &old_aik, now_ms).unwrap();

        // Tamper with new key bytes
        payload.new_aik_ed_pub[0] ^= 0xFF;

        let err = payload.verify(&old_aik.verifying_keys());
        assert!(matches!(err, Err(TnError::BadSignature)));
    }
}
