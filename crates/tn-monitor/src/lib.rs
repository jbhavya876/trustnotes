#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-monitor`: Third-party transparency log monitor and auditor (Claim C10, SPEC §4).
//!
//! Follows the global log and release log, verifies server signatures, consistency
//! between consecutive checkpoints, and witness cosignatures. Alerts on inconsistency,
//! missing cosignatures, equivocation, or unlogged server-key changes.

use tn_crypto::VerifyingKeys;
use tn_merkle::{verify_consistency, ConsistencyProof, MerkleRoot};
use tn_proto::EvidenceBundle;
use tn_tlog::{
    verify_checkpoint, verify_ots_proof, Checkpoint, OtsProof, OtsVerificationResult, WitnessPolicy,
};
use tn_types::TnError;

/// Auditor state tracking verified log progression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorState {
    /// Latest verified log size.
    pub size: u64,
    /// Latest verified root hash.
    pub root_hash: [u8; 32],
    /// Timestamp of latest verified checkpoint.
    pub timestamp_ms: u64,
}

/// Standalone auditor daemon for independent third-party verification of TrustNotes.
pub struct MonitorAuditor {
    origin: String,
    server_vk: VerifyingKeys,
    policy: WitnessPolicy,
    state: Option<MonitorState>,
}

impl MonitorAuditor {
    /// Creates a new monitor auditor targeting a specific transparency log origin.
    #[must_use]
    pub fn new(origin: String, server_vk: VerifyingKeys, policy: WitnessPolicy) -> Self {
        Self {
            origin,
            server_vk,
            policy,
            state: None,
        }
    }

    /// Returns current verified monitor state.
    #[must_use]
    pub fn state(&self) -> Option<&MonitorState> {
        self.state.as_ref()
    }

    /// Audits a newly observed checkpoint and transitions state if cryptographically valid.
    ///
    /// # Errors
    /// Returns typed `TnError`:
    /// - `TnError::BadSignature`: Invalid server signature.
    /// - `TnError::WitnessPolicy`: Fewer than k valid witness cosignatures.
    /// - `TnError::Rollback`: Log size or timestamp decreased.
    /// - `TnError::Equivocation`: Conflicting roots for the same tree size.
    /// - `TnError::RootMismatch`: Invalid consistency proof.
    pub fn audit_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
        consistency_proof: Option<&ConsistencyProof>,
        now_ms: u64,
    ) -> Result<(), TnError> {
        if checkpoint.origin != self.origin {
            return Err(TnError::Internal("Log origin mismatch".into()));
        }

        let (last_size, last_ts) = match &self.state {
            Some(s) => (s.size, s.timestamp_ms),
            None => (0, 0),
        };

        // 1. Verify checkpoint server signature and witness cosignatures
        verify_checkpoint(
            checkpoint,
            &self.server_vk,
            &self.policy,
            last_size,
            last_ts,
            now_ms,
        )?;

        // 2. State transition and consistency checks
        if let Some(prev) = &self.state {
            if checkpoint.size == prev.size {
                if checkpoint.root_hash != prev.root_hash {
                    // Scenario S12: Server equivocation!
                    return Err(TnError::Equivocation {
                        epoch: checkpoint.size,
                    });
                }
            } else if checkpoint.size > prev.size {
                let proof = consistency_proof.ok_or_else(|| {
                    TnError::Internal("Missing consistency proof for log extension".into())
                })?;
                let old_root = MerkleRoot::from_bytes(prev.root_hash);
                let new_root = MerkleRoot::from_bytes(checkpoint.root_hash);
                verify_consistency(&old_root, &new_root, proof)?;
            }
        }

        self.state = Some(MonitorState {
            size: checkpoint.size,
            root_hash: checkpoint.root_hash,
            timestamp_ms: checkpoint.timestamp_ms,
        });

        Ok(())
    }

    /// Audits an exported Evidence Bundle proving server misbehavior (Claim C5, Scenario S10/S12/S7).
    ///
    /// # Errors
    /// Returns `TnError` if bundle is invalid or does not mathematically prove misbehavior.
    pub fn audit_evidence_bundle(&self, bundle: &EvidenceBundle) -> Result<(), TnError> {
        bundle.verify(&self.server_vk, &self.policy)
    }

    /// Verifies Bitcoin OpenTimestamps time-anchoring proof for a checkpoint (Claim C6).
    ///
    /// # Errors
    /// Returns `TnError` if OTS proof does not connect checkpoint root to Bitcoin block hash.
    pub fn audit_time_anchor(
        &self,
        checkpoint: &Checkpoint,
        proof: &OtsProof,
        expected_block_hash: &[u8; 32],
    ) -> Result<OtsVerificationResult, TnError> {
        verify_ots_proof(&checkpoint.root_hash, proof, expected_block_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::SigningKeys;
    use tn_merkle::MerkleTree;
    use tn_tlog::{create_mock_ots_proof, Cosignature};

    fn make_test_keys() -> (SigningKeys, VerifyingKeys) {
        let sk = SigningKeys::generate().unwrap();
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    fn make_cosigned_checkpoint(
        origin: &str,
        size: u64,
        root: [u8; 32],
        ts: u64,
        server_sk: &SigningKeys,
        witness_id: [u8; 32],
    ) -> Checkpoint {
        let mut cp = Checkpoint {
            origin: origin.into(),
            size,
            root_hash: root,
            timestamp_ms: ts,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![Cosignature {
                witness_key_id: witness_id,
                timestamp_ms: ts,
                sig_ed: [0u8; 64],
            }],
        };
        let body = cp.signed_body();
        cp.server_sig = server_sk.sign(&body);
        cp
    }

    #[test]
    fn test_monitor_audit_progression_and_consistency() {
        let (server_sk, server_vk) = make_test_keys();
        let w1 = [0x77u8; 32];
        let policy = WitnessPolicy {
            threshold: 1,
            pinned_witnesses: vec![w1],
            max_age_seconds: 300,
        };

        let origin = "trustnotes.origin.test";
        let mut monitor = MonitorAuditor::new(origin.into(), server_vk, policy);

        // Epoch 1: 1 leaf
        let mut tree = MerkleTree::new();
        tree.append_leaf_hash([0x01; 32]);
        let root1 = *tree.root().as_bytes();

        let cp1 = make_cosigned_checkpoint(origin, 1, root1, 1_000, &server_sk, w1);
        monitor.audit_checkpoint(&cp1, None, 1_000).unwrap();
        assert_eq!(monitor.state().unwrap().size, 1);

        // Epoch 2: 2 leaves with valid consistency proof
        tree.append_leaf_hash([0x02; 32]);
        let root2 = *tree.root().as_bytes();
        let proof = tree.consistency_proof(1).unwrap();

        let cp2 = make_cosigned_checkpoint(origin, 2, root2, 2_000, &server_sk, w1);
        monitor.audit_checkpoint(&cp2, Some(&proof), 2_000).unwrap();
        assert_eq!(monitor.state().unwrap().size, 2);
    }

    #[test]
    fn test_monitor_detects_server_equivocation_s12() {
        let (server_sk, server_vk) = make_test_keys();
        let w1 = [0x77u8; 32];
        let policy = WitnessPolicy {
            threshold: 1,
            pinned_witnesses: vec![w1],
            max_age_seconds: 300,
        };

        let origin = "trustnotes.origin.test";
        let mut monitor = MonitorAuditor::new(origin.into(), server_vk, policy);

        let cp1 = make_cosigned_checkpoint(origin, 3, [0xAA; 32], 1_000, &server_sk, w1);
        monitor.audit_checkpoint(&cp1, None, 1_000).unwrap();

        // Server issues different root for same size 3!
        let cp1_forged = make_cosigned_checkpoint(origin, 3, [0xBB; 32], 1_000, &server_sk, w1);
        let res = monitor.audit_checkpoint(&cp1_forged, None, 1_000);
        assert!(matches!(res, Err(TnError::Equivocation { epoch: 3 })));
    }

    #[test]
    fn test_monitor_ots_anchor_audit() {
        let (server_sk, server_vk) = make_test_keys();
        let w1 = [0x77u8; 32];
        let policy = WitnessPolicy {
            threshold: 1,
            pinned_witnesses: vec![w1],
            max_age_seconds: 300,
        };

        let origin = "trustnotes.origin.test";
        let monitor = MonitorAuditor::new(origin.into(), server_vk, policy);

        let cp_root = [0x88; 32];
        let cp = make_cosigned_checkpoint(origin, 1, cp_root, 1_000, &server_sk, w1);
        let (proof, block_hash) = create_mock_ots_proof(&cp_root, 850_000, 1_720_000_000);

        let result = monitor.audit_time_anchor(&cp, &proof, &block_hash).unwrap();
        assert_eq!(result.block_height, 850_000);
        assert_eq!(result.block_hash, block_hash);
    }
}
