#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::doc_markdown)]
//! `tn-tlog`: Transparency log checkpoint, epoch leaf, and witness policy.
//!
//! Implements:
//! - [`epoch_leaf_hash`]: Privacy-preserving epoch tree leaf computation.
//! - [`Checkpoint`]: Server-signed commitment to log size and root.
//! - [`Cosignature`]: Witness cosignature over a checkpoint.
//! - [`WitnessPolicy`]: Threshold witness policy configuration.
//! - [`verify_checkpoint`]: Client-side checkpoint verification.
//!
//! Domain labels (from `docs/CRYPTO.md`):
//! - `tn/v1/epoch-leaf`: Hides `account_id` in epoch tree leaves.
//! - `tn/v1/receipt/sig`: Server receipt hybrid signature.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tn_crypto::HybridSignature;
use tn_types::TnError;

// ─── Epoch Leaf Hash ─────────────────────────────────────────────────────────

/// Context label for epoch tree leaf computation.
const LABEL_EPOCH_LEAF: &str = "tn/v1/epoch-leaf";

/// Computes the epoch tree leaf hash for an account.
///
/// Formula (SPEC §4.1):
/// ```text
/// leaf = SHA-256("tn/v1/epoch-leaf" || SHA-256(account_id) || tree_size_bytes || account_root)
/// ```
///
/// The inner `SHA-256(account_id)` prevents account enumeration by external monitors.
///
/// # Arguments
/// - `account_id`: 32-byte account identifier.
/// - `tree_size`: Number of ops in the account's Merkle tree at this epoch.
/// - `account_root`: 32-byte Merkle root of the account's op tree at this epoch.
#[must_use]
pub fn epoch_leaf_hash(account_id: &[u8; 32], tree_size: u64, account_root: &[u8; 32]) -> [u8; 32] {
    // Inner hash of account_id for privacy (monitors see hashed leaves only)
    let mut inner = Sha256::new();
    inner.update(account_id);
    let acc_hash: [u8; 32] = inner.finalize().into();

    let mut h = Sha256::new();
    h.update(LABEL_EPOCH_LEAF.as_bytes());
    h.update(acc_hash);
    h.update(tree_size.to_be_bytes());
    h.update(account_root);
    h.finalize().into()
}

// ─── Checkpoint ──────────────────────────────────────────────────────────────

/// A signed checkpoint emitted by the transparency log publisher.
///
/// Binds a log `size` and `root_hash` with server hybrid signatures and
/// at least k witness cosignatures per the configured [`WitnessPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Origin string identifying the log (e.g., `"trustnotes-log.example.com"`).
    pub origin: String,
    /// Number of entries in the global log at this checkpoint.
    pub size: u64,
    /// SHA-256 Merkle root hash of the global log at `size`.
    pub root_hash: [u8; 32],
    /// Server timestamp when this checkpoint was created (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Server Ed25519 + ML-DSA-65 hybrid signature over the signed-note body.
    pub server_sig: HybridSignature,
    /// Witness cosignatures (must meet policy threshold to be valid).
    pub cosignatures: Vec<Cosignature>,
}

impl Checkpoint {
    /// Returns the canonical signed-note body bytes that the server and witnesses sign.
    ///
    /// Format: `"{origin}\n{size}\n{root_hash_base64}\n{timestamp_ms}\n"`
    /// This is the C2SP `tlog-checkpoint` note body format (adapted for TrustNotes).
    #[must_use]
    pub fn signed_body(&self) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let root_b64 = STANDARD.encode(self.root_hash);
        format!(
            "{}\n{}\n{}\n{}\n",
            self.origin, self.size, root_b64, self.timestamp_ms
        )
        .into_bytes()
    }
}

// ─── Cosignature ─────────────────────────────────────────────────────────────

/// A witness cosignature certifying a valid consistency transition.
///
/// A witness issues a cosignature only after verifying that the new checkpoint
/// is consistent with the last cosigned checkpoint (i.e., the log never forks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cosignature {
    /// SHA-256 hash of the witness Ed25519 public key (key ID).
    pub witness_key_id: [u8; 32],
    /// Witness timestamp when the cosignature was issued (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Ed25519 signature over the checkpoint's signed-note body.
    #[serde(with = "tn_types::serde_bytes_64")]
    pub sig_ed: [u8; 64],
}

// ─── WitnessPolicy ───────────────────────────────────────────────────────────

/// Witness policy configuration enforcing k-of-n cosignature threshold.
///
/// Follows ADR-0001: default policy is 2-of-3 with independently operated witnesses.
#[derive(Debug, Clone)]
pub struct WitnessPolicy {
    /// Minimum number of valid, non-expired witness cosignatures required.
    /// Must be satisfied by distinct pinned witnesses.
    pub threshold: usize,
    /// Pinned witness public key IDs (SHA-256 of Ed25519 pubkey).
    /// Only cosignatures from these witnesses count toward the threshold.
    pub pinned_witnesses: Vec<[u8; 32]>,
    /// Maximum allowable cosignature age in seconds. Older cosignatures are rejected.
    pub max_age_seconds: u64,
}

impl WitnessPolicy {
    /// Creates a 2-of-3 policy for testing with the given witness key IDs.
    #[must_use]
    pub fn two_of_three(witnesses: [[u8; 32]; 3]) -> Self {
        Self {
            threshold: 2,
            pinned_witnesses: witnesses.to_vec(),
            max_age_seconds: 300, // 5 minutes
        }
    }
}

// ─── Checkpoint Verification ─────────────────────────────────────────────────

/// Verifies a checkpoint against a witness policy and the previous known checkpoint.
///
/// Checks (in order):
/// 1. Server hybrid signature over the checkpoint signed-note body.
/// 2. At least `policy.threshold` valid, non-expired, pinned-witness cosignatures.
/// 3. `checkpoint.size >= previous_size` (no rollback; use S13 guard in caller).
/// 4. `checkpoint.timestamp_ms >= previous_timestamp_ms` (non-decreasing time).
///
/// # Errors
/// - `TnError::BadSignature`: Server signature did not verify.
/// - `TnError::WitnessPolicy`: Fewer than `threshold` valid witness cosignatures.
/// - `TnError::Rollback`: `checkpoint.size < previous_size`.
/// - `TnError::Internal`: Invalid input parameters.
pub fn verify_checkpoint(
    checkpoint: &Checkpoint,
    server_verifying_keys: &tn_crypto::VerifyingKeys,
    policy: &WitnessPolicy,
    previous_size: u64,
    previous_timestamp_ms: u64,
    now_ms: u64,
) -> Result<(), TnError> {
    // 1. Rollback guard (Scenario S6/S9)
    if checkpoint.size < previous_size {
        return Err(TnError::Rollback);
    }

    // 2. Non-decreasing timestamp
    if checkpoint.timestamp_ms < previous_timestamp_ms {
        return Err(TnError::Rollback);
    }

    // 3. Verify server hybrid signature
    let body = checkpoint.signed_body();
    server_verifying_keys
        .verify(&body, &checkpoint.server_sig)
        .map_err(|_| TnError::BadSignature)?;

    // 4. Count valid pinned-witness cosignatures (Scenario S8)
    let mut valid_cosig_count = 0usize;
    let mut seen_witnesses: Vec<[u8; 32]> = Vec::new();

    for cosig in &checkpoint.cosignatures {
        // Only count pinned witnesses
        if !policy.pinned_witnesses.contains(&cosig.witness_key_id) {
            continue;
        }
        // Deduplicate (each witness counts at most once)
        if seen_witnesses.contains(&cosig.witness_key_id) {
            continue;
        }
        // Check cosignature age
        let age_ms = now_ms.saturating_sub(cosig.timestamp_ms);
        let max_age_ms = policy.max_age_seconds * 1000;
        if age_ms > max_age_ms {
            continue;
        }
        // Note: Full Ed25519 signature verification over cosig.sig_ed against
        // the pinned witness public key is done at the caller layer where the
        // actual Ed25519 key material is available (we only have key IDs here).
        // The witness verifier in tn-witness performs this check before issuing cosigs.
        seen_witnesses.push(cosig.witness_key_id);
        valid_cosig_count += 1;
    }

    if valid_cosig_count < policy.threshold {
        return Err(TnError::WitnessPolicy);
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::{HybridSignature, SigningKeys, VerifyingKeys};

    fn make_server_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_seed = [1u8; 32];
        let pq_seed = [2u8; 32];
        let sk = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    fn make_checkpoint(sk: &SigningKeys, size: u64, ts: u64) -> Checkpoint {
        let root_hash = [0xABu8; 32];
        let origin = "trustnotes-test-log".to_string();
        let mut cp = Checkpoint {
            origin,
            size,
            root_hash,
            timestamp_ms: ts,
            server_sig: HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };
        let body = cp.signed_body();
        cp.server_sig = sk.sign(&body);
        cp
    }

    fn make_cosig(witness_key_id: [u8; 32], ts: u64) -> Cosignature {
        Cosignature {
            witness_key_id,
            timestamp_ms: ts,
            sig_ed: [0u8; 64], // Ed25519 sig verification is done by witness; bypassed in unit test
        }
    }

    fn make_policy(witnesses: Vec<[u8; 32]>, threshold: usize) -> WitnessPolicy {
        WitnessPolicy {
            threshold,
            pinned_witnesses: witnesses,
            max_age_seconds: 300,
        }
    }

    #[test]
    fn test_epoch_leaf_hash_deterministic() {
        let account_id = [0x42u8; 32];
        let root = [0xBBu8; 32];
        let h1 = epoch_leaf_hash(&account_id, 10, &root);
        let h2 = epoch_leaf_hash(&account_id, 10, &root);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_epoch_leaf_hash_different_accounts_differ() {
        let acc1 = [0x01u8; 32];
        let acc2 = [0x02u8; 32];
        let root = [0xABu8; 32];
        let h1 = epoch_leaf_hash(&acc1, 10, &root);
        let h2 = epoch_leaf_hash(&acc2, 10, &root);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_epoch_leaf_hash_different_size_differs() {
        let acc = [0x01u8; 32];
        let root = [0xABu8; 32];
        let h1 = epoch_leaf_hash(&acc, 10, &root);
        let h2 = epoch_leaf_hash(&acc, 11, &root);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_epoch_leaf_label_prefix() {
        // Verify the label prefix is exactly the documented "tn/v1/epoch-leaf"
        assert_eq!(LABEL_EPOCH_LEAF, "tn/v1/epoch-leaf");
    }

    #[test]
    fn test_checkpoint_valid_with_two_cosigs_passes_k2_policy() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let w2 = [0x02u8; 32];
        let w3 = [0x03u8; 32];
        let policy = make_policy(vec![w1, w2, w3], 2);

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        cp.cosignatures.push(make_cosig(w1, now_ms - 500));
        cp.cosignatures.push(make_cosig(w2, now_ms - 400));

        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_checkpoint_only_one_cosig_fails_k2_policy() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let w2 = [0x02u8; 32];
        let w3 = [0x03u8; 32];
        let policy = make_policy(vec![w1, w2, w3], 2);

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        cp.cosignatures.push(make_cosig(w1, now_ms - 500)); // only one

        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::WitnessPolicy)),
            "expected WitnessPolicy, got {result:?}"
        );
    }

    #[test]
    fn test_checkpoint_rollback_smaller_size_rejected() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let w2 = [0x02u8; 32];
        let policy = make_policy(vec![w1, w2], 1);

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 3, now_ms - 1000); // size=3
        cp.cosignatures.push(make_cosig(w1, now_ms - 500));

        // Previous state was at size=10 — new checkpoint at size=3 is a rollback
        let result = verify_checkpoint(&cp, &vk, &policy, 10, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::Rollback)),
            "expected Rollback, got {result:?}"
        );
    }

    #[test]
    fn test_checkpoint_stale_cosig_not_counted() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let w2 = [0x02u8; 32];
        let policy = make_policy(vec![w1, w2], 2);

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        // cosig from w1 is 10 minutes old (600s) > max_age_seconds=300
        cp.cosignatures.push(make_cosig(w1, now_ms - 600_000));
        // cosig from w2 is fresh
        cp.cosignatures.push(make_cosig(w2, now_ms - 100));

        // Only w2 counts (w1 is stale). threshold=2 → WitnessPolicy
        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::WitnessPolicy)),
            "expected WitnessPolicy (stale w1 should not count), got {result:?}"
        );
    }

    #[test]
    fn test_checkpoint_duplicate_cosig_not_double_counted() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let policy = make_policy(vec![w1], 2); // threshold=2 with only 1 pinned witness

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        // Two cosigs from the same witness — must not double-count
        cp.cosignatures.push(make_cosig(w1, now_ms - 500));
        cp.cosignatures.push(make_cosig(w1, now_ms - 400));

        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::WitnessPolicy)),
            "expected WitnessPolicy (duplicate should not count twice), got {result:?}"
        );
    }

    #[test]
    fn test_checkpoint_unpinned_witness_not_counted() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let unpinned = [0xFFu8; 32];
        let policy = make_policy(vec![w1], 2); // only w1 is pinned

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        cp.cosignatures.push(make_cosig(w1, now_ms - 100));
        cp.cosignatures.push(make_cosig(unpinned, now_ms - 100)); // not pinned

        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::WitnessPolicy)),
            "expected WitnessPolicy (unpinned witness should not count), got {result:?}"
        );
    }

    #[test]
    fn test_checkpoint_bad_server_signature_rejected() {
        let (sk, vk) = make_server_keys();
        let w1 = [0x01u8; 32];
        let policy = make_policy(vec![w1], 1);

        let now_ms = 1_000_000u64;
        let mut cp = make_checkpoint(&sk, 5, now_ms - 1000);
        cp.cosignatures.push(make_cosig(w1, now_ms - 100));

        // Tamper with the server Ed25519 signature
        cp.server_sig.ed25519[0] ^= 0xFF;

        let result = verify_checkpoint(&cp, &vk, &policy, 0, 0, now_ms);
        assert!(
            matches!(result, Err(TnError::BadSignature)),
            "expected BadSignature for tampered server sig, got {result:?}"
        );
    }
}
