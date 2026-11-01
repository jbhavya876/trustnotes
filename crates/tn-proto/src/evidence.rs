#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cryptographic Evidence Bundle definition and verification (Claim C5, ADR-0001, `docs/cddl/evidence_bundle.cddl`).
//!
//! Provides verifiable proofs of server misbehavior for:
//! - S10: Missed Merge Deadline (op receipted but omitted past MMD).
//! - S12: Equivocation (conflicting roots published for same epoch/size).
//! - S7: Split View (inconsistent checkpoints served to different parties).

use serde::{Deserialize, Serialize};
use tn_crypto::VerifyingKeys;
use tn_tlog::{verify_checkpoint, Checkpoint, WitnessPolicy};
use tn_types::{cbor, Id32, TnError};

use crate::Receipt;

/// Discriminant for evidence kind per `docs/cddl/evidence_bundle.cddl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EvidenceKind {
    /// S10: Op receipted with MMD, but missing from witnessed epoch log.
    MergeDeadlineMissed = 1,
    /// S12: Server published two conflicting roots for the same size/epoch.
    Equivocation = 2,
    /// S7: Inconsistent checkpoints served to different devices.
    SplitView = 3,
}

/// Evidence payload proving a missed merge deadline (Scenario S10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeDeadlineEvidence {
    /// Server-signed receipt committing to inclusion by `mmd_epoch`.
    pub receipt: Receipt,
    /// Witnessed checkpoints proving the log has progressed past `mmd_epoch`.
    pub checkpoints: Vec<Checkpoint>,
}

/// Evidence payload proving server equivocation (Scenario S12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// Target epoch/size at which equivocation occurred.
    pub epoch: u64,
    /// First published root hash.
    pub root_a: [u8; 32],
    /// Second conflicting root hash.
    pub root_b: [u8; 32],
    /// Full checkpoint containing root_a.
    pub checkpoint_a: Checkpoint,
    /// Full checkpoint containing root_b.
    pub checkpoint_b: Checkpoint,
}

/// Evidence payload proving split-view fork (Scenario S7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitViewEvidence {
    /// Checkpoint observed by Device A.
    pub device_a_checkpoint: Checkpoint,
    /// Incompatible checkpoint observed by Device B.
    pub device_b_checkpoint: Checkpoint,
}

/// Typed evidence variant matching CDDL `BundleEvidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleEvidence {
    /// S10: Missed merge deadline.
    MergeDeadline(MergeDeadlineEvidence),
    /// S12: Server equivocation.
    Equivocation(EquivocationEvidence),
    /// S7: Split view fork.
    SplitView(SplitViewEvidence),
}

/// Self-contained cryptographic Evidence Bundle proving operator misbehavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle version (1).
    pub v: u32,
    /// Numeric kind matching `EvidenceKind`.
    pub bundle_kind: u8,
    /// Associated account identifier.
    pub account_id: Id32,
    /// Unix timestamp in milliseconds when bundle was generated.
    pub created_at: u64,
    /// Underlying evidence payloads.
    pub evidence: BundleEvidence,
}

impl EvidenceBundle {
    /// Creates a missed merge deadline evidence bundle (Scenario S10).
    #[must_use]
    pub fn new_missed_merge_deadline(
        account_id: Id32,
        receipt: Receipt,
        checkpoints: Vec<Checkpoint>,
        created_at: u64,
    ) -> Self {
        Self {
            v: 1,
            bundle_kind: EvidenceKind::MergeDeadlineMissed as u8,
            account_id,
            created_at,
            evidence: BundleEvidence::MergeDeadline(MergeDeadlineEvidence {
                receipt,
                checkpoints,
            }),
        }
    }

    /// Creates an equivocation evidence bundle (Scenario S12).
    #[must_use]
    pub fn new_equivocation(
        account_id: Id32,
        epoch: u64,
        checkpoint_a: Checkpoint,
        checkpoint_b: Checkpoint,
        created_at: u64,
    ) -> Self {
        Self {
            v: 1,
            bundle_kind: EvidenceKind::Equivocation as u8,
            account_id,
            created_at,
            evidence: BundleEvidence::Equivocation(EquivocationEvidence {
                epoch,
                root_a: checkpoint_a.root_hash,
                root_b: checkpoint_b.root_hash,
                checkpoint_a,
                checkpoint_b,
            }),
        }
    }

    /// Creates a split-view evidence bundle (Scenario S7).
    #[must_use]
    pub fn new_split_view(
        account_id: Id32,
        checkpoint_a: Checkpoint,
        checkpoint_b: Checkpoint,
        created_at: u64,
    ) -> Self {
        Self {
            v: 1,
            bundle_kind: EvidenceKind::SplitView as u8,
            account_id,
            created_at,
            evidence: BundleEvidence::SplitView(SplitViewEvidence {
                device_a_checkpoint: checkpoint_a,
                device_b_checkpoint: checkpoint_b,
            }),
        }
    }

    /// Serializes bundle to canonical CBOR format.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Deserializes bundle from canonical CBOR format.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }

    /// Independently validates this evidence bundle against server verifying keys and witness policy.
    ///
    /// # Errors
    /// Fails closed: returns `TnError` if signatures are invalid, thresholds unmet, or misbehavior not proved.
    pub fn verify(&self, server_vk: &VerifyingKeys, policy: &WitnessPolicy) -> Result<(), TnError> {
        match &self.evidence {
            BundleEvidence::MergeDeadline(ev) => {
                // 1. Verify server receipt signature
                ev.receipt.verify(server_vk)?;

                // 2. Verify all attached checkpoints have valid server signatures and meet witness policy
                let mut passed_mmd = false;
                for cp in &ev.checkpoints {
                    verify_checkpoint(cp, server_vk, policy, 0, 0, self.created_at)?;
                    if cp.size >= ev.receipt.mmd_epoch {
                        passed_mmd = true;
                    }
                }

                if !passed_mmd {
                    return Err(TnError::Internal(
                        "No checkpoint in bundle proves log advanced past MMD epoch".into(),
                    ));
                }

                Ok(())
            }
            BundleEvidence::Equivocation(ev) => {
                // 1. Verify server signatures on both checkpoints
                let body_a = ev.checkpoint_a.signed_body();
                server_vk
                    .verify(&body_a, &ev.checkpoint_a.server_sig)
                    .map_err(|_| TnError::BadSignature)?;

                let body_b = ev.checkpoint_b.signed_body();
                server_vk
                    .verify(&body_b, &ev.checkpoint_b.server_sig)
                    .map_err(|_| TnError::BadSignature)?;

                // 2. Both checkpoints must have same size but different root hash
                if ev.checkpoint_a.size != ev.checkpoint_b.size {
                    return Err(TnError::Internal(
                        "Equivocation evidence checkpoints have different sizes".into(),
                    ));
                }
                if ev.checkpoint_a.root_hash == ev.checkpoint_b.root_hash {
                    return Err(TnError::Internal(
                        "Equivocation evidence checkpoints have identical roots".into(),
                    ));
                }

                Ok(())
            }
            BundleEvidence::SplitView(ev) => {
                // 1. Verify server signatures on both checkpoints
                let body_a = ev.device_a_checkpoint.signed_body();
                server_vk
                    .verify(&body_a, &ev.device_a_checkpoint.server_sig)
                    .map_err(|_| TnError::BadSignature)?;

                let body_b = ev.device_b_checkpoint.signed_body();
                server_vk
                    .verify(&body_b, &ev.device_b_checkpoint.server_sig)
                    .map_err(|_| TnError::BadSignature)?;

                if ev.device_a_checkpoint.size == ev.device_b_checkpoint.size
                    && ev.device_a_checkpoint.root_hash == ev.device_b_checkpoint.root_hash
                {
                    return Err(TnError::Internal(
                        "Split view checkpoints are identical".into(),
                    ));
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::SigningKeys;
    use tn_tlog::Cosignature;

    fn make_test_keys() -> (SigningKeys, VerifyingKeys) {
        let sk = SigningKeys::generate().unwrap();
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    #[test]
    fn test_equivocation_evidence_verification() {
        let (server_sk, server_vk) = make_test_keys();
        let account_id = Id32::from_bytes([0x11; 32]);
        let now_ms = 1_700_000_000_000u64;

        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];

        // Sign checkpoint A
        let mut cp_a = Checkpoint {
            origin: "test.origin".into(),
            size: 5,
            root_hash: root_a,
            timestamp_ms: now_ms,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };
        let body_a = cp_a.signed_body();
        cp_a.server_sig = server_sk.sign(&body_a);

        // Sign checkpoint B
        let mut cp_b = Checkpoint {
            origin: "test.origin".into(),
            size: 5,
            root_hash: root_b,
            timestamp_ms: now_ms,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };
        let body_b = cp_b.signed_body();
        cp_b.server_sig = server_sk.sign(&body_b);

        let bundle = EvidenceBundle::new_equivocation(account_id, 5, cp_a, cp_b, now_ms);

        let policy = WitnessPolicy {
            threshold: 1,
            pinned_witnesses: vec![],
            max_age_seconds: 300,
        };

        // Verification passes
        bundle.verify(&server_vk, &policy).unwrap();

        // Roundtrip CBOR
        let cbor = bundle.to_cbor().unwrap();
        let decoded = EvidenceBundle::from_cbor(&cbor).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn test_missed_merge_deadline_evidence_verification() {
        let (server_sk, server_vk) = make_test_keys();
        let account_id = Id32::from_bytes([0x11; 32]);
        let now_ms = 1_700_000_000_000u64;

        // Server receipt with mmd_epoch = 3
        let receipt = Receipt::sign(
            account_id,
            Id32::from_bytes([0x99; 32]),
            0,
            1,
            now_ms,
            3,
            &server_sk,
        )
        .unwrap();

        let w1 = [0x55u8; 32];
        let mut cp = Checkpoint {
            origin: "test.origin".into(),
            size: 4, // size 4 > mmd_epoch 3
            root_hash: [0x42; 32],
            timestamp_ms: now_ms,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![Cosignature {
                witness_key_id: w1,
                timestamp_ms: now_ms,
                sig_ed: [0u8; 64],
            }],
        };
        let body = cp.signed_body();
        cp.server_sig = server_sk.sign(&body);

        let bundle =
            EvidenceBundle::new_missed_merge_deadline(account_id, receipt, vec![cp], now_ms);

        let policy = WitnessPolicy {
            threshold: 1,
            pinned_witnesses: vec![w1],
            max_age_seconds: 300,
        };

        bundle.verify(&server_vk, &policy).unwrap();
    }
}
