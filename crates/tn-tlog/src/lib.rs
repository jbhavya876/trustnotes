#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-tlog`: Transparency log checkpoint formats, cosignatures, and witness policies.
//!
//! Implements C2SP `tlog-checkpoint`, `tlog-cosignature`, and `tlog-witness` semantics.
//! Checkpoints are signed notes committing to a log size and root hash. Independent
//! witnesses verify consistency between consecutive checkpoints before adding their
//! cosignature.
//!
//! # M0 Status
//!
//! Skeleton crate. Checkpoint and cosignature parsers, witness policy types, and the
//! client verification pipeline will be implemented in M3.

use tn_types::TnError;

/// A signed checkpoint emitted by the transparency log publisher.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Origin string identifying the log.
    pub origin: String,
    /// Number of entries committed to by this checkpoint.
    pub size: u64,
    /// Merkle root hash of the log at `size`.
    pub root_hash: [u8; 32],
    /// Server timestamp (Unix milliseconds).
    pub timestamp_ms: u64,
}

/// A witness cosignature certifying a valid consistency transition.
#[derive(Debug, Clone)]
pub struct Cosignature {
    /// Identifier (public key hash) of the cosigning witness.
    pub witness_id: [u8; 32],
    /// Witness timestamp (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Ed25519 signature over the signed note body.
    pub sig: [u8; 64],
}

/// Witness policy configuration (e.g. 2-of-3 threshold).
#[derive(Debug, Clone)]
pub struct WitnessPolicy {
    /// Minimum number of valid witness cosignatures required.
    pub threshold: usize,
    /// Pinned witness public keys.
    pub pinned_witnesses: Vec<[u8; 32]>,
    /// Maximum allowable cosignature age in seconds.
    pub max_age_seconds: u64,
}

/// Verify a checkpoint against a witness policy and previous state.
///
/// # Errors
///
/// Returns [`TnError::WitnessPolicy`] if threshold is not met.
/// Returns [`TnError::Internal`] until M3.
pub fn verify_checkpoint(
    _checkpoint: &Checkpoint,
    _cosignatures: &[Cosignature],
    _policy: &WitnessPolicy,
) -> Result<(), TnError> {
    Err(TnError::Internal("not implemented — M3".to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_m0() {
        assert_eq!(1 + 1, 2);
    }
}
