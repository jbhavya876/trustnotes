#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Release Transparency Log and reproducible build attestations (Claim C7, SPEC §4).
//!
//! Enforces:
//! - Multi-builder reproducible build attestations (minimum 2 independent builders).
//! - Release transparency log RFC 9162 Merkle tree.
//! - Offline binary self-verification (`tn self-verify`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tn_crypto::labels::{LABEL_BUILDER_SIG, LABEL_RELEASE_LEAF};
use tn_crypto::{derive_device_id, HybridSignature, SigningKeys, VerifyingKeys};
use tn_merkle::{verify_inclusion, InclusionProof, MerkleRoot, MerkleTree};
use tn_types::{cbor, Id32, TnError};

/// Envelope hashed and signed by an independent reproducible builder.
#[derive(Debug, Serialize, Deserialize)]
struct BuilderAttestationEnvelope<'a> {
    builder_id: Id32,
    build_time: u64,
    version: &'a str,
    target: &'a str,
    binary_hash: [u8; 32],
}

/// Signed attestation from an independent builder verifying byte-for-byte reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderAttestation {
    /// Builder identifier (SHA-256 of verifying keys).
    pub builder_id: Id32,
    /// Unix timestamp when build finished (ms).
    pub build_time: u64,
    /// Release version tag (e.g. "v0.1.0").
    pub version: String,
    /// Target triple.
    pub target: String,
    /// SHA-256 digest of the reproducible binary.
    pub binary_hash: [u8; 32],
    /// Builder hybrid signature over `LABEL_BUILDER_SIG || canonical_cbor(envelope)`.
    pub signature: HybridSignature,
}

impl BuilderAttestation {
    /// Authors and signs a builder attestation.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if serialization fails.
    pub fn sign(
        version: &str,
        target: &str,
        binary_hash: [u8; 32],
        build_time: u64,
        builder_keys: &SigningKeys,
    ) -> Result<Self, TnError> {
        let vk = builder_keys.verifying_keys();
        let builder_id = derive_device_id(&vk.ed25519_bytes, &vk.mldsa65_bytes);

        let env = BuilderAttestationEnvelope {
            builder_id,
            build_time,
            version,
            target,
            binary_hash,
        };
        let cbor_bytes = cbor::encode_canonical(&env)?;
        let mut msg = Vec::with_capacity(LABEL_BUILDER_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_BUILDER_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let signature = builder_keys.sign(&msg);

        Ok(Self {
            builder_id,
            build_time,
            version: version.to_string(),
            target: target.to_string(),
            binary_hash,
            signature,
        })
    }

    /// Verifies builder signature against expected builder verifying keys.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` if signature does not verify.
    pub fn verify(&self, builder_vk: &VerifyingKeys) -> Result<(), TnError> {
        let derived_id = derive_device_id(&builder_vk.ed25519_bytes, &builder_vk.mldsa65_bytes);
        if derived_id != self.builder_id {
            return Err(TnError::BadSignature);
        }

        let env = BuilderAttestationEnvelope {
            builder_id: self.builder_id,
            build_time: self.build_time,
            version: &self.version,
            target: &self.target,
            binary_hash: self.binary_hash,
        };
        let cbor_bytes = cbor::encode_canonical(&env)?;
        let mut msg = Vec::with_capacity(LABEL_BUILDER_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_BUILDER_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        builder_vk.verify(&msg, &self.signature)
    }
}

/// Release log entry recorded in the Release Transparency Log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEntry {
    /// Semantic version.
    pub version: String,
    /// Target platform triple.
    pub target: String,
    /// SHA-256 hash of the binary.
    pub binary_hash: [u8; 32],
    /// Independent builder attestations (must have $\ge 2$ distinct valid signatures).
    pub attestations: Vec<BuilderAttestation>,
}

impl ReleaseEntry {
    /// Computes the RFC 9162 Merkle leaf hash for this release entry.
    #[must_use]
    pub fn compute_leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(LABEL_RELEASE_LEAF.as_bytes());
        h.update(self.binary_hash);
        h.update(self.version.as_bytes());
        h.update(self.target.as_bytes());
        h.finalize().into()
    }

    /// Validates that at least `min_builders` distinct trusted builders signed this release.
    ///
    /// # Errors
    /// Returns `TnError::WitnessPolicy` or `TnError::BadSignature` if threshold unmet.
    pub fn verify_attestations(
        &self,
        trusted_builders: &[VerifyingKeys],
        min_builders: usize,
    ) -> Result<(), TnError> {
        let mut verified_builders = HashSet::new();

        for attestation in &self.attestations {
            if attestation.binary_hash != self.binary_hash
                || attestation.version != self.version
                || attestation.target != self.target
            {
                continue;
            }

            // Match against trusted builder keys
            for builder_vk in trusted_builders {
                let id = derive_device_id(&builder_vk.ed25519_bytes, &builder_vk.mldsa65_bytes);
                if id == attestation.builder_id && attestation.verify(builder_vk).is_ok() {
                    verified_builders.insert(id);
                    break;
                }
            }
        }

        if verified_builders.len() < min_builders {
            return Err(TnError::WitnessPolicy);
        }

        Ok(())
    }
}

/// In-memory Release Transparency Log builder.
#[derive(Default)]
pub struct ReleaseLog {
    entries: Vec<ReleaseEntry>,
    tree: MerkleTree,
}

impl ReleaseLog {
    /// Creates an empty ReleaseLog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            tree: MerkleTree::new(),
        }
    }

    /// Appends a new verified release entry to the log.
    pub fn append_entry(&mut self, entry: ReleaseEntry) -> u64 {
        let leaf = entry.compute_leaf_hash();
        let idx = self.entries.len() as u64;
        self.entries.push(entry);
        self.tree.append_leaf_hash(leaf);
        idx
    }

    /// Returns current Merkle root of the release log.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        self.tree.root()
    }

    /// Returns the number of entries in the log.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Returns true if log has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Generates an inclusion proof for the release entry at `index`.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if index is out of bounds.
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, TnError> {
        self.tree.inclusion_proof(index)
    }

    /// Returns a reference to all entries.
    #[must_use]
    pub fn entries(&self) -> &[ReleaseEntry] {
        &self.entries
    }

    /// Converts the log into a serializable manifest.
    #[must_use]
    pub fn to_manifest(&self) -> ReleaseLogManifest {
        ReleaseLogManifest {
            entries: self.entries.clone(),
        }
    }

    /// Reconstructs the release log and Merkle tree from a manifest.
    #[must_use]
    pub fn from_manifest(manifest: ReleaseLogManifest) -> Self {
        let mut log = Self::new();
        for entry in manifest.entries {
            log.append_entry(entry);
        }
        log
    }
}

/// Serializable container for release log entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseLogManifest {
    /// All release entries in sequential order.
    pub entries: Vec<ReleaseEntry>,
}

impl ReleaseLogManifest {
    /// Serializes manifest to canonical CBOR.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on serialization error.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Deserializes manifest from canonical CBOR.
    ///
    /// # Errors
    /// Returns `TnError::Decode` on parse error.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }
}

/// Executes full end-to-end binary self-verification (Claim C7).
///
/// # Checks:
/// 1. Computes SHA-256 of `binary_bytes` and asserts equality with `entry.binary_hash`.
/// 2. Asserts `entry.version == version` and `entry.target == target`.
/// 3. Validates builder attestations against `trusted_builders` ($\ge \text{min\_builders}$).
/// 4. Validates RFC 9162 Merkle inclusion proof against `trusted_release_root`.
///
/// # Errors
/// Returns typed `TnError` if binary hash differs, builders are untrusted, or proof fails.
#[allow(clippy::too_many_arguments)]
pub fn verify_binary_authenticity(
    binary_bytes: &[u8],
    version: &str,
    target: &str,
    entry: &ReleaseEntry,
    proof: &InclusionProof,
    release_root: &MerkleRoot,
    trusted_builders: &[VerifyingKeys],
    min_builders: usize,
) -> Result<(), TnError> {
    // 1. Verify byte-for-byte SHA-256 of the binary
    let computed_hash: [u8; 32] = Sha256::digest(binary_bytes).into();
    if computed_hash != entry.binary_hash {
        return Err(TnError::CiphertextTampered);
    }

    // 2. Verify metadata matches
    if entry.version != version || entry.target != target {
        return Err(TnError::OrderViolation);
    }

    // 3. Verify independent builder attestations
    entry.verify_attestations(trusted_builders, min_builders)?;

    // 4. Verify RFC 9162 Merkle inclusion in the Release Transparency Log
    let leaf_hash = entry.compute_leaf_hash();
    verify_inclusion(&leaf_hash, proof, release_root)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_keys() -> (SigningKeys, VerifyingKeys) {
        let sk = SigningKeys::generate().unwrap();
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    #[test]
    fn test_release_log_and_binary_self_verification_happy_path() {
        let (b1_sk, b1_vk) = make_test_keys();
        let (b2_sk, b2_vk) = make_test_keys();
        let trusted_builders = vec![b1_vk, b2_vk];

        let binary_bytes = b"BINARY_PAYLOAD_V0.1.0_M4_RELEASE";
        let binary_hash: [u8; 32] = Sha256::digest(binary_bytes).into();
        let version = "v0.1.0";
        let target = "x86_64-pc-windows-msvc";
        let now_ms = 1_700_000_000_000u64;

        // Builder 1 and 2 independently attest
        let att1 = BuilderAttestation::sign(version, target, binary_hash, now_ms, &b1_sk).unwrap();
        let att2 =
            BuilderAttestation::sign(version, target, binary_hash, now_ms + 10, &b2_sk).unwrap();

        let entry = ReleaseEntry {
            version: version.to_string(),
            target: target.to_string(),
            binary_hash,
            attestations: vec![att1, att2],
        };

        // Append to release transparency log
        let mut log = ReleaseLog::new();
        let idx = log.append_entry(entry.clone());
        let release_root = log.root();
        let proof = log.inclusion_proof(idx).unwrap();

        // Binary self-verification succeeds
        verify_binary_authenticity(
            binary_bytes,
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

    #[test]
    fn test_tampered_binary_fails_self_verify() {
        let (b1_sk, b1_vk) = make_test_keys();
        let (b2_sk, b2_vk) = make_test_keys();
        let trusted_builders = vec![b1_vk, b2_vk];

        let binary_bytes = b"ORIGINAL_BINARY";
        let binary_hash: [u8; 32] = Sha256::digest(binary_bytes).into();
        let version = "v0.1.0";
        let target = "x86_64-unknown-linux-gnu";

        let att1 = BuilderAttestation::sign(version, target, binary_hash, 1_000, &b1_sk).unwrap();
        let att2 = BuilderAttestation::sign(version, target, binary_hash, 1_000, &b2_sk).unwrap();

        let entry = ReleaseEntry {
            version: version.to_string(),
            target: target.to_string(),
            binary_hash,
            attestations: vec![att1, att2],
        };

        let mut log = ReleaseLog::new();
        let idx = log.append_entry(entry.clone());
        let release_root = log.root();
        let proof = log.inclusion_proof(idx).unwrap();

        // Attacker modified the binary
        let tampered_bytes = b"BACKDOORED_BINARY";
        let res = verify_binary_authenticity(
            tampered_bytes,
            version,
            target,
            &entry,
            &proof,
            &release_root,
            &trusted_builders,
            2,
        );
        assert!(matches!(res, Err(TnError::CiphertextTampered)));
    }
}
