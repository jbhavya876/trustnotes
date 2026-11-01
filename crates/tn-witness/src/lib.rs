#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Independent witness verification logic and state tracker (ADR-0001, SPEC §4.2).
//!
//! Enforces:
//! - RFC 9162 consistency proof verification between sequential log checkpoints.
//! - Strict monotonic size: rollback attempts immediately rejected with `TnError::Rollback`.
//! - Equivocation detection: same size with different root hash emits `TnError::Equivocation`.
//! - Cosignature generation using witness Ed25519 key.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tn_crypto::VerifyingKeys;
use tn_merkle::{verify_consistency, ConsistencyProof, MerkleRoot};
use tn_tlog::{Checkpoint, Cosignature};
use tn_types::TnError;

/// State tracked by a witness for a specific transparency log origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessOriginState {
    /// Latest verified log size.
    pub size: u64,
    /// Latest verified root hash.
    pub root_hash: [u8; 32],
    /// Timestamp of the latest verified checkpoint (ms).
    pub timestamp_ms: u64,
}

/// Witness verifier enforcing consistency and cosigning legitimate checkpoints.
pub struct Witness {
    signing_key: SigningKey,
    key_id: [u8; 32],
    origins: HashMap<String, WitnessOriginState>,
}

impl Witness {
    /// Creates a new Witness from a 32-byte Ed25519 private seed.
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.as_bytes());
        let key_id: [u8; 32] = hasher.finalize().into();

        Self {
            signing_key,
            key_id,
            origins: HashMap::new(),
        }
    }

    /// Returns the witness key identifier (SHA-256 of Ed25519 public key).
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Returns the raw Ed25519 public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// Evaluates a checkpoint proposal and returns a signed cosignature if valid.
    ///
    /// # Errors
    /// - `TnError::BadSignature`: Server signature on checkpoint proposal is invalid.
    /// - `TnError::Rollback`: Proposed size < known size, or timestamp decreased.
    /// - `TnError::Equivocation`: Same size proposed with conflicting root hash.
    /// - `TnError::RootMismatch`: Consistency proof invalid or missing when size increased.
    pub fn cosign_checkpoint(
        &mut self,
        server_vk: &VerifyingKeys,
        checkpoint: &Checkpoint,
        consistency_proof: Option<&ConsistencyProof>,
        now_ms: u64,
    ) -> Result<Cosignature, TnError> {
        // 1. Verify server hybrid signature on the checkpoint signed note body
        let body = checkpoint.signed_body();
        server_vk
            .verify(&body, &checkpoint.server_sig)
            .map_err(|_| TnError::BadSignature)?;

        // 2. Reject future-dated checkpoints beyond allowed clock skew (60s)
        if checkpoint.timestamp_ms > now_ms + 60_000 {
            return Err(TnError::OrderViolation);
        }

        // 3. Inspect previous known state for this log origin
        if let Some(prev) = self.origins.get(&checkpoint.origin) {
            // Rollback guard
            if checkpoint.size < prev.size {
                return Err(TnError::Rollback);
            }

            // Timestamp non-decreasing
            if checkpoint.timestamp_ms < prev.timestamp_ms {
                return Err(TnError::Rollback);
            }

            // Equivocation check: same size must match previous root
            if checkpoint.size == prev.size {
                if checkpoint.root_hash != prev.root_hash {
                    return Err(TnError::Equivocation {
                        epoch: checkpoint.size,
                    });
                }
                // Root is identical, re-cosign
                return Ok(self.sign_cosignature(checkpoint, now_ms));
            }

            // Size increased: must provide valid consistency proof
            let proof = consistency_proof.ok_or(TnError::RootMismatch)?;
            let old_root = MerkleRoot::from_bytes(prev.root_hash);
            let new_root = MerkleRoot::from_bytes(checkpoint.root_hash);

            verify_consistency(&old_root, &new_root, proof)?;
        }

        // 4. Update witness state
        self.origins.insert(
            checkpoint.origin.clone(),
            WitnessOriginState {
                size: checkpoint.size,
                root_hash: checkpoint.root_hash,
                timestamp_ms: checkpoint.timestamp_ms,
            },
        );

        // 5. Emit signed cosignature
        Ok(self.sign_cosignature(checkpoint, now_ms))
    }

    fn sign_cosignature(&self, checkpoint: &Checkpoint, now_ms: u64) -> Cosignature {
        let body = checkpoint.signed_body();
        let sig = self.signing_key.sign(&body);
        Cosignature {
            witness_key_id: self.key_id,
            timestamp_ms: now_ms,
            sig_ed: sig.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::SigningKeys;
    use tn_merkle::MerkleTree;

    fn make_test_checkpoint(
        keys: &SigningKeys,
        origin: &str,
        size: u64,
        root_hash: [u8; 32],
        now_ms: u64,
    ) -> Checkpoint {
        let mut cp = Checkpoint {
            origin: origin.to_string(),
            size,
            root_hash,
            timestamp_ms: now_ms,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };
        let body = cp.signed_body();
        cp.server_sig = keys.sign(&body);
        cp
    }

    #[test]
    fn test_witness_happy_path_and_consistency() {
        let server_keys = SigningKeys::generate().unwrap();
        let server_vk = server_keys.verifying_keys();

        let mut witness = Witness::new(&[0x77u8; 32]);
        let now_ms = 1_700_000_000_000u64;

        // Tree size 1
        let mut tree = MerkleTree::new();
        tree.append(b"epoch 0");
        let cp1 = make_test_checkpoint(
            &server_keys,
            "origin.test",
            1,
            *tree.root().as_bytes(),
            now_ms,
        );

        let cosig1 = witness
            .cosign_checkpoint(&server_vk, &cp1, None, now_ms)
            .unwrap();
        assert_eq!(cosig1.witness_key_id, witness.key_id());

        // Tree size 2: valid consistency proof
        tree.append(b"epoch 1");
        let proof = tree.consistency_proof(1).unwrap();
        let cp2 = make_test_checkpoint(
            &server_keys,
            "origin.test",
            2,
            *tree.root().as_bytes(),
            now_ms + 1000,
        );

        let cosig2 = witness
            .cosign_checkpoint(&server_vk, &cp2, Some(&proof), now_ms + 1000)
            .unwrap();
        assert_eq!(cosig2.witness_key_id, witness.key_id());
    }

    #[test]
    fn test_witness_rejects_rollback() {
        let server_keys = SigningKeys::generate().unwrap();
        let server_vk = server_keys.verifying_keys();

        let mut witness = Witness::new(&[0x88u8; 32]);
        let now_ms = 1_700_000_000_000u64;

        let cp1 = make_test_checkpoint(&server_keys, "origin.test", 5, [1u8; 32], now_ms);
        witness
            .cosign_checkpoint(&server_vk, &cp1, None, now_ms)
            .unwrap();

        // Rollback attempt to size 4
        let cp2 = make_test_checkpoint(&server_keys, "origin.test", 4, [2u8; 32], now_ms + 1000);
        let res = witness.cosign_checkpoint(&server_vk, &cp2, None, now_ms + 1000);
        assert!(matches!(res, Err(TnError::Rollback)));
    }

    #[test]
    fn test_witness_detects_equivocation() {
        let server_keys = SigningKeys::generate().unwrap();
        let server_vk = server_keys.verifying_keys();

        let mut witness = Witness::new(&[0x99u8; 32]);
        let now_ms = 1_700_000_000_000u64;

        let cp1 = make_test_checkpoint(&server_keys, "origin.test", 5, [1u8; 32], now_ms);
        witness
            .cosign_checkpoint(&server_vk, &cp1, None, now_ms)
            .unwrap();

        // Equivocation: same size 5, different root
        let cp_equiv = make_test_checkpoint(&server_keys, "origin.test", 5, [9u8; 32], now_ms);
        let res = witness.cosign_checkpoint(&server_vk, &cp_equiv, None, now_ms);
        assert!(matches!(res, Err(TnError::Equivocation { epoch: 5 })));
    }
}
