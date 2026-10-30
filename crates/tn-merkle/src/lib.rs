#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-merkle`: Append-only Merkle tree implementation for trustnotes.
//!
//! Provides the sparse Merkle tree and inclusion/consistency proof primitives
//! used by the account tree, the epoch tree, and the witness log.
//!
//! # M0 Status
//!
//! Skeleton crate. All types and functions will be implemented in M1.
//!
//! # Key Concepts (M1+)
//!
//! - **Leaf**: SHA-256 hash of a CBOR-encoded op (or a zero hash for empty leaves).
//! - **Node hash**: `SHA-256(0x01 || left_child || right_child)`.
//! - **Leaf hash**: `SHA-256(0x00 || leaf_data)`.
//! - **Inclusion proof**: A sibling path from leaf to root.
//! - **Consistency proof**: Demonstrates that tree at size `n` is a prefix of tree at size `m`.
//!
//! Domain separation prefix `0x00`/`0x01` follows RFC 6962 / Certificate Transparency conventions.

use tn_types::TnError;

/// A SHA-256 Merkle tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Create a `MerkleRoot` from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An inclusion proof for a single leaf.
pub struct InclusionProof {
    /// Sibling hashes from leaf to root (left-to-right = bottom-to-top).
    pub siblings: Vec<[u8; 32]>,
    /// 0-indexed leaf position this proof is for.
    pub leaf_index: u64,
}

/// Verify a Merkle inclusion proof.
///
/// # Errors
///
/// Returns [`TnError::RootMismatch`] if the computed root does not match `expected_root`.
/// Returns [`TnError::Internal`] until M1.
pub fn verify_inclusion(
    _leaf_hash: &[u8; 32],
    _proof: &InclusionProof,
    _expected_root: &MerkleRoot,
) -> Result<(), TnError> {
    Err(TnError::Internal("not implemented — M1".to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_m0() {
        assert_eq!(1 + 1, 2);
    }
}
