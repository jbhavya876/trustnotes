#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Device enrollment packages and HPKE (X-Wing) delivery (Claim C8, `docs/cddl/enrollment_package.cddl`).
//!
//! Delivers Account Root (AR) and cross-signed `DeviceCertificate` to an enrolling device
//! encrypted to the new device's Device Transport Key (DTK) using X-Wing hybrid post-quantum KEM.

use serde::{Deserialize, Serialize};
use tn_crypto::aead::{open_raw, seal_raw};
use tn_crypto::kem::{
    decapsulate, encapsulate, HybridCiphertext, HybridKemPrivateKey, HybridKemPublicKey,
};
use tn_crypto::labels::LABEL_DEVICE_ENROLLMENT;
use tn_crypto::{HybridSignature, SigningKeys, VerifyingKeys};
use tn_types::{cbor, Id32, TnError};
use zeroize::Zeroize;

use crate::DeviceCertificate;

/// Inner payload delivered securely to the enrolling device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentPayload {
    /// Schema version (1).
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// 32-byte Account Root entropy (zeroized after import).
    pub account_root: [u8; 32],
    /// Cross-signed device certificate authorizing the new device.
    pub device_cert: DeviceCertificate,
}

impl Drop for EnrollmentPayload {
    fn drop(&mut self) {
        self.account_root.zeroize();
    }
}

/// Envelope signed by the enrolling device sender.
#[derive(Debug, Serialize)]
struct EnrollmentEnvelope<'a> {
    device_id_new: Id32,
    device_id_sender: Id32,
    created_at: u64,
    kem_ciphertext: &'a HybridCiphertext,
    encrypted_payload: &'a [u8],
}

/// Self-contained encrypted package delivering the account root to a new device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentPackage {
    /// Schema version (1).
    pub v: u32,
    /// New device identifier.
    pub device_id_new: Id32,
    /// Enrolling existing device identifier.
    pub device_id_sender: Id32,
    /// Unix timestamp in milliseconds.
    pub created_at: u64,
    /// X-Wing hybrid KEM ciphertext.
    pub kem_ciphertext: HybridCiphertext,
    /// AEAD ciphertext containing canonical CBOR `EnrollmentPayload`.
    pub encrypted_payload: Vec<u8>,
    /// Hybrid signature from existing enrolling device.
    pub signature: HybridSignature,
}

impl EnrollmentPackage {
    /// Creates and seals an enrollment package for a new device.
    ///
    /// # Errors
    /// Returns `TnError` if encapsulation, serialization, or AEAD fails.
    pub fn seal(
        account_id: Id32,
        account_root: [u8; 32],
        device_cert: DeviceCertificate,
        new_device_dtk: &HybridKemPublicKey,
        sender_device_id: Id32,
        sender_keys: &SigningKeys,
        created_at: u64,
    ) -> Result<Self, TnError> {
        let device_id_new = device_cert.device_id;

        // 1. Post-quantum hybrid KEM encapsulation
        let (shared_key, kem_ciphertext) = encapsulate(new_device_dtk)?;

        // 2. Serialize and AEAD-seal payload under shared_key
        let payload = EnrollmentPayload {
            v: 1,
            account_id,
            account_root,
            device_cert,
        };
        let payload_cbor = cbor::encode_canonical(&payload)?;

        let encrypted_payload = seal_raw(
            &shared_key,
            LABEL_DEVICE_ENROLLMENT.as_bytes(),
            &payload_cbor,
        )?;

        // 3. Author sender hybrid signature over envelope
        let env = EnrollmentEnvelope {
            device_id_new,
            device_id_sender: sender_device_id,
            created_at,
            kem_ciphertext: &kem_ciphertext,
            encrypted_payload: &encrypted_payload,
        };
        let env_cbor = cbor::encode_canonical(&env)?;

        let mut msg = Vec::with_capacity(LABEL_DEVICE_ENROLLMENT.len() + env_cbor.len());
        msg.extend_from_slice(LABEL_DEVICE_ENROLLMENT.as_bytes());
        msg.extend_from_slice(&env_cbor);

        let signature = sender_keys.sign(&msg);

        Ok(Self {
            v: 1,
            device_id_new,
            device_id_sender: sender_device_id,
            created_at,
            kem_ciphertext,
            encrypted_payload,
            signature,
        })
    }

    /// Opens and decrypts the enrollment package on the new device.
    ///
    /// # Checks:
    /// 1. Verifies sender signature using `sender_vk`.
    /// 2. Decapsulates shared secret using `dtk_priv` and `dtk_pub`.
    /// 3. Decrypts `encrypted_payload` and deserializes `EnrollmentPayload`.
    /// 4. Asserts `account_id` matches expected account.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` or `TnError::CiphertextTampered` if verification fails.
    pub fn open(
        &self,
        dtk_priv: &HybridKemPrivateKey,
        dtk_pub: &HybridKemPublicKey,
        sender_vk: &VerifyingKeys,
    ) -> Result<EnrollmentPayload, TnError> {
        // 1. Verify sender signature
        let env = EnrollmentEnvelope {
            device_id_new: self.device_id_new,
            device_id_sender: self.device_id_sender,
            created_at: self.created_at,
            kem_ciphertext: &self.kem_ciphertext,
            encrypted_payload: &self.encrypted_payload,
        };
        let env_cbor = cbor::encode_canonical(&env)?;

        let mut msg = Vec::with_capacity(LABEL_DEVICE_ENROLLMENT.len() + env_cbor.len());
        msg.extend_from_slice(LABEL_DEVICE_ENROLLMENT.as_bytes());
        msg.extend_from_slice(&env_cbor);

        sender_vk.verify(&msg, &self.signature)?;

        // 2. Post-quantum hybrid KEM decapsulation
        let shared_key = decapsulate(dtk_priv, dtk_pub, &self.kem_ciphertext)?;

        // 3. Open AEAD ciphertext
        let payload_cbor = open_raw(
            &shared_key,
            LABEL_DEVICE_ENROLLMENT.as_bytes(),
            &self.encrypted_payload,
        )?;

        let payload: EnrollmentPayload = cbor::decode_canonical(&payload_cbor)?;
        if payload.device_cert.device_id != self.device_id_new {
            return Err(TnError::CiphertextTampered);
        }

        Ok(payload)
    }

    /// Serializes package to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on serialization error.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Deserializes package from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on parse error.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::kem::HybridKemKeyPair;
    use tn_crypto::SigningKeys;

    #[test]
    fn test_enrollment_package_seal_and_open_roundtrip() {
        let account_id = Id32::from_bytes([0xAA; 32]);
        let account_root = [0x55; 32];
        let now_ms = 1_700_000_000_000u64;

        // Existing device (sender)
        let sender_sk = SigningKeys::generate().unwrap();
        let sender_vk = sender_sk.verifying_keys();
        let sender_id =
            tn_crypto::derive_device_id(&sender_vk.ed25519_bytes, &sender_vk.mldsa65_bytes);

        // New device DTK
        let new_dtk = HybridKemKeyPair::generate().unwrap();
        let new_dsk = SigningKeys::generate().unwrap();
        let new_dsk_vk = new_dsk.verifying_keys();

        // AIK for signing certificate
        let aik_sk = SigningKeys::generate().unwrap();
        let cert = DeviceCertificate::issue(
            account_id,
            &new_dsk_vk,
            new_dtk.public_key.to_bytes(),
            now_ms,
            None,
            &aik_sk,
        )
        .unwrap();

        // Sender seals enrollment package
        let pkg = EnrollmentPackage::seal(
            account_id,
            account_root,
            cert.clone(),
            &new_dtk.public_key,
            sender_id,
            &sender_sk,
            now_ms,
        )
        .unwrap();

        // Roundtrip to CBOR bytes
        let cbor_bytes = pkg.to_cbor().unwrap();
        let decoded_pkg = EnrollmentPackage::from_cbor(&cbor_bytes).unwrap();
        assert_eq!(pkg, decoded_pkg);

        // New device opens package
        let opened = decoded_pkg
            .open(&new_dtk.private_key, &new_dtk.public_key, &sender_vk)
            .unwrap();

        assert_eq!(opened.account_id, account_id);
        assert_eq!(opened.account_root, account_root);
        assert_eq!(opened.device_cert, cert);
    }
}
