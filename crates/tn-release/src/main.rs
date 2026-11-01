#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-release`: Reproducible build verification, signing ceremonies, and release log entries (Claim C7).
//!
//! Tools for independent builders to reproduce release artifacts byte-for-byte,
//! perform offline signing ceremonies, and append entries to the release transparency log.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tn_crypto::{SigningKeys, VerifyingKeys};
use tn_merkle::InclusionProof;
use tn_proto::release::{verify_binary_authenticity, BuilderAttestation, ReleaseEntry};
use tn_types::TnError;

/// Creates an independent builder attestation for a compiled binary.
///
/// # Errors
/// Returns `TnError` if reading binary or signing fails.
pub fn attest_binary(
    binary_path: &Path,
    version: &str,
    target: &str,
    now_ms: u64,
    builder_keys: &SigningKeys,
) -> Result<BuilderAttestation, TnError> {
    let bytes = fs::read(binary_path)
        .map_err(|e| TnError::Internal(format!("Failed to read binary for attestation: {e}")))?;
    let binary_hash: [u8; 32] = Sha256::digest(&bytes).into();

    BuilderAttestation::sign(version, target, binary_hash, now_ms, builder_keys)
}

/// Verifies a release binary against an inclusion proof and Release Log root.
///
/// # Errors
/// Returns `TnError` if binary hash is invalid, builders untrusted, or proof fails.
#[allow(clippy::too_many_arguments)]
pub fn verify_release_artifact(
    binary_path: &Path,
    version: &str,
    target: &str,
    entry: &ReleaseEntry,
    proof: &InclusionProof,
    release_root: &[u8; 32],
    trusted_builders: &[VerifyingKeys],
    min_builders: usize,
) -> Result<(), TnError> {
    let bytes = fs::read(binary_path)
        .map_err(|e| TnError::Internal(format!("Failed to read binary for verification: {e}")))?;

    let root = tn_merkle::MerkleRoot::from_bytes(*release_root);

    verify_binary_authenticity(
        &bytes,
        version,
        target,
        entry,
        proof,
        &root,
        trusted_builders,
        min_builders,
    )
}

fn main() {
    println!("tn-release: reproducible build and release transparency manager");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tn_proto::release::ReleaseLog;

    fn make_test_keys() -> (SigningKeys, VerifyingKeys) {
        let sk = SigningKeys::generate().unwrap();
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    #[test]
    fn test_release_attest_and_verify_pipeline() {
        let tmp = NamedTempFile::new().unwrap();
        let binary_bytes = b"REPRODUCIBLE_RELEASE_BINARY_CONTENTS";
        fs::write(tmp.path(), binary_bytes).unwrap();

        let (b1_sk, b1_vk) = make_test_keys();
        let (b2_sk, b2_vk) = make_test_keys();
        let trusted_builders = vec![b1_vk, b2_vk];

        let version = "v0.1.0";
        let target = "x86_64-pc-windows-msvc";
        let now_ms = 1_700_000_000_000u64;

        // Two independent builders attest the same binary
        let att1 = attest_binary(tmp.path(), version, target, now_ms, &b1_sk).unwrap();
        let att2 = attest_binary(tmp.path(), version, target, now_ms + 5, &b2_sk).unwrap();

        let entry = ReleaseEntry {
            version: version.to_string(),
            target: target.to_string(),
            binary_hash: att1.binary_hash,
            attestations: vec![att1, att2],
        };

        let mut log = ReleaseLog::new();
        let idx = log.append_entry(entry.clone());
        let release_root = *log.root().as_bytes();
        let proof = log.inclusion_proof(idx).unwrap();

        // Verification passes
        verify_release_artifact(
            tmp.path(),
            version,
            target,
            &entry,
            &proof,
            &release_root,
            &trusted_builders,
            2,
        )
        .unwrap();
    }
}
