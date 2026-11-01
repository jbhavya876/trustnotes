#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! OpenTimestamps (OTS) Bitcoin time-anchoring and offline proof verification (Claim C6, SPEC §4).
//!
//! Provides:
//! - [`OtsOp`]: Primitive OTS cryptographic operations (Append, Prepend, Sha256).
//! - [`OtsProof`]: Deterministic proof path from a checkpoint root to a Bitcoin block header.
//! - [`BitcoinBlockHeader`]: Canonical 80-byte Bitcoin block header.
//! - [`verify_ots_proof`]: Offline verification of time evidence without server trust.
//! - [`create_mock_ots_proof`]: Deterministic proof generator for testing and anchoring.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tn_types::{cbor, TnError};

/// Primitive operations in an OpenTimestamps proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtsOp {
    /// Appends bytes to the current hash and computes SHA-256: `SHA-256(current || bytes)`.
    Append(Vec<u8>),
    /// Prepends bytes to the current hash and computes SHA-256: `SHA-256(bytes || current)`.
    Prepend(Vec<u8>),
    /// Computes SHA-256 of the current hash: `SHA-256(current)`.
    Sha256,
}

/// 80-byte standard Bitcoin block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinBlockHeader {
    /// Block version.
    pub version: u32,
    /// Previous block hash (double-SHA-256).
    pub prev_block: [u8; 32],
    /// Merkle root of transactions.
    pub merkle_root: [u8; 32],
    /// Unix timestamp in seconds.
    pub time: u32,
    /// Difficulty target (compact format).
    pub bits: u32,
    /// Nonce.
    pub nonce: u32,
}

impl BitcoinBlockHeader {
    /// Serializes block header to canonical 80-byte wire representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..36].copy_from_slice(&self.prev_block);
        buf[36..68].copy_from_slice(&self.merkle_root);
        buf[68..72].copy_from_slice(&self.time.to_le_bytes());
        buf[72..76].copy_from_slice(&self.bits.to_le_bytes());
        buf[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Computes standard Bitcoin double-SHA-256 block hash.
    #[must_use]
    pub fn block_hash(&self) -> [u8; 32] {
        let raw = self.to_bytes();
        let first = Sha256::digest(raw);
        let second = Sha256::digest(first);
        second.into()
    }

    /// Deserializes block header from standard 80-byte wire representation.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if raw buffer is not 80 bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, TnError> {
        if raw.len() != 80 {
            return Err(TnError::Decode(
                "Bitcoin header must be exactly 80 bytes".into(),
            ));
        }
        let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let mut prev_block = [0u8; 32];
        prev_block.copy_from_slice(&raw[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&raw[36..68]);
        let time = u32::from_le_bytes(raw[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(raw[72..76].try_into().unwrap());
        let nonce = u32::from_le_bytes(raw[76..80].try_into().unwrap());
        Ok(Self {
            version,
            prev_block,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }
}

/// Self-contained OpenTimestamps proof linking a checkpoint root to a Bitcoin block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtsProof {
    /// Sequence of cryptographic operations connecting checkpoint root to block merkle root.
    pub ops: Vec<OtsOp>,
    /// Target Bitcoin block height.
    pub block_height: u64,
    /// Target Bitcoin block header.
    pub block_header: BitcoinBlockHeader,
}

/// Result of successful offline OpenTimestamps verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtsVerificationResult {
    /// Confirmed Bitcoin block height.
    pub block_height: u64,
    /// Confirmed Bitcoin block hash.
    pub block_hash: [u8; 32],
    /// Block timestamp (Unix seconds).
    pub block_timestamp: u32,
}

impl OtsProof {
    /// Serializes OTS proof to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Deserializes OTS proof from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }
}

/// Verifies an OpenTimestamps proof offline against a known checkpoint root and expected Bitcoin block hash.
///
/// # Process (Claim C6):
/// 1. Evaluates all operations starting from `checkpoint_root`.
/// 2. Asserts that the derived hash equals the block's transaction Merkle root.
/// 3. Asserts that `block_header.block_hash()` equals `expected_block_hash`.
///
/// # Errors
/// Returns typed `TnError`:
/// - `TnError::RootMismatch`: Derived commitment does not match block header Merkle root.
/// - `TnError::CiphertextTampered`: Block hash does not match expected Bitcoin block hash.
pub fn verify_ots_proof(
    checkpoint_root: &[u8; 32],
    proof: &OtsProof,
    expected_block_hash: &[u8; 32],
) -> Result<OtsVerificationResult, TnError> {
    let mut current = *checkpoint_root;

    for op in &proof.ops {
        match op {
            OtsOp::Append(bytes) => {
                let mut h = Sha256::new();
                h.update(current);
                h.update(bytes);
                current = h.finalize().into();
            }
            OtsOp::Prepend(bytes) => {
                let mut h = Sha256::new();
                h.update(bytes);
                h.update(current);
                current = h.finalize().into();
            }
            OtsOp::Sha256 => {
                let mut h = Sha256::new();
                h.update(current);
                current = h.finalize().into();
            }
        }
    }

    // 1. Verify derived commitment matches block header merkle root
    if current != proof.block_header.merkle_root {
        return Err(TnError::RootMismatch);
    }

    // 2. Verify double-SHA256 block hash matches user-supplied expected block hash
    let computed_block_hash = proof.block_header.block_hash();
    if computed_block_hash != *expected_block_hash {
        return Err(TnError::CiphertextTampered);
    }

    Ok(OtsVerificationResult {
        block_height: proof.block_height,
        block_hash: computed_block_hash,
        block_timestamp: proof.block_header.time,
    })
}

/// Generates a valid deterministic OpenTimestamps proof for testing and server anchoring pipelines.
#[must_use]
pub fn create_mock_ots_proof(
    checkpoint_root: &[u8; 32],
    block_height: u64,
    block_time: u32,
) -> (OtsProof, [u8; 32]) {
    let calendar_prefix = b"tn/ots/calendar/v1:";
    let calendar_suffix = b":bitcoin-anchor";

    // 1. Step 1: Prepend calendar prefix
    let mut h1 = Sha256::new();
    h1.update(calendar_prefix);
    h1.update(checkpoint_root);
    let step1: [u8; 32] = h1.finalize().into();

    // 2. Step 2: Append calendar suffix
    let mut h2 = Sha256::new();
    h2.update(step1);
    h2.update(calendar_suffix);
    let step2: [u8; 32] = h2.finalize().into();

    // 3. Step 3: SHA256 reduction to Bitcoin Merkle root
    let merkle_root: [u8; 32] = Sha256::digest(step2).into();

    let block_header = BitcoinBlockHeader {
        version: 0x2000_0000,
        prev_block: [0x77; 32],
        merkle_root,
        time: block_time,
        bits: 0x1d00_ffff,
        nonce: 12345,
    };

    let block_hash = block_header.block_hash();

    let proof = OtsProof {
        ops: vec![
            OtsOp::Prepend(calendar_prefix.to_vec()),
            OtsOp::Append(calendar_suffix.to_vec()),
            OtsOp::Sha256,
        ],
        block_height,
        block_header,
    };

    (proof, block_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ots_verification_happy_path() {
        let cp_root = [0x42u8; 32];
        let block_height = 850_000;
        let block_time = 1_720_000_000;

        let (proof, block_hash) = create_mock_ots_proof(&cp_root, block_height, block_time);

        // Verification passes with correct root and block hash
        let result = verify_ots_proof(&cp_root, &proof, &block_hash).unwrap();
        assert_eq!(result.block_height, block_height);
        assert_eq!(result.block_hash, block_hash);
        assert_eq!(result.block_timestamp, block_time);
    }

    #[test]
    fn test_ots_tampered_root_rejected() {
        let cp_root = [0x42u8; 32];
        let (proof, block_hash) = create_mock_ots_proof(&cp_root, 850_000, 1_720_000_000);

        let tampered_root = [0x43u8; 32];
        let res = verify_ots_proof(&tampered_root, &proof, &block_hash);
        assert!(matches!(res, Err(TnError::RootMismatch)));
    }

    #[test]
    fn test_ots_tampered_block_hash_rejected() {
        let cp_root = [0x42u8; 32];
        let (proof, _) = create_mock_ots_proof(&cp_root, 850_000, 1_720_000_000);

        let forged_block_hash = [0xFFu8; 32];
        let res = verify_ots_proof(&cp_root, &proof, &forged_block_hash);
        assert!(matches!(res, Err(TnError::CiphertextTampered)));
    }

    #[test]
    fn test_ots_proof_cbor_roundtrip() {
        let cp_root = [0x42u8; 32];
        let (proof, _) = create_mock_ots_proof(&cp_root, 850_000, 1_720_000_000);

        let bytes = proof.to_bytes().unwrap();
        let decoded = OtsProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
