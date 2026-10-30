#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Operation wire structures, canonical CBOR encoding, hashing, and payload management.
//!
//! Fully compliant with `docs/cddl/op.cddl` and `docs/SPEC.md` §2.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tn_crypto::labels::{LABEL_AEAD_OP, LABEL_OP_ID};
use tn_types::{cbor, Id16, Id32, OpKind, TnError};

use crate::hlc::Hlc;

/// Unencrypted note payload stored inside the AEAD ciphertext `ct`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Schema version, currently 1.
    pub schema_v: u32,
    /// Note title in plain UTF-8 text.
    pub title: String,
    /// Markdown body text.
    pub body_md: String,
    /// List of tag strings.
    pub tags: Vec<String>,
    /// Optional notebook identifier (16 bytes UUID).
    pub notebook_id: Option<Id16>,
    /// Flags bitmask (bit 0 = pinned, bit 1 = trashed).
    pub flags: u32,
    /// Creation timestamp (Unix ms).
    pub created_at: u64,
    /// Modification timestamp (Unix ms).
    pub updated_at: u64,
}

impl Payload {
    /// Flag bit 0: pinned note.
    pub const FLAG_PINNED: u32 = 1 << 0;
    /// Flag bit 1: trashed note.
    pub const FLAG_TRASHED: u32 = 1 << 1;

    /// Checks if note is pinned.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        (self.flags & Self::FLAG_PINNED) != 0
    }

    /// Checks if note is trashed.
    #[must_use]
    pub fn is_trashed(&self) -> bool {
        (self.flags & Self::FLAG_TRASHED) != 0
    }
}

/// The authenticated header of an operation covering all metadata and `ct_hash`.
///
/// Hashing this struct with prefix `tn/v1/op-id` produces the unique `op_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpHeader {
    /// Protocol version, always 1.
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Device identifier that authored this op.
    pub device_id: Id32,
    /// Monotonically increasing counter in this device lane.
    pub lane_seq: u64,
    /// Identifier of the prior op in this device lane (None for first op).
    pub lane_prev: Option<Id32>,
    /// Hybrid logical clock timestamp `[wall_ms, counter]`.
    pub hlc: Hlc,
    /// Operation kind (1..6).
    pub kind: OpKind,
    /// Target object identifier (16 bytes).
    pub object_id: Id16,
    /// Note Key wrapped under Vault Key (present on Put).
    pub nk_wrap: Option<Vec<u8>>,
    /// 24-byte nonce used for payload AEAD encryption.
    pub nonce: [u8; 24],
    /// Causal dependencies (prior `op_id`s that this op supersedes or follows).
    pub deps: Vec<Id32>,
    /// Cryptographic digest of the ciphertext `SHA-256(ct)`.
    pub ct_hash: Id32,
}

mod serde_sig64 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| D::Error::custom(format!("expected 64 bytes, got {}", v.len())))
    }
}

/// A full operation record in the `TrustNotes` operation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    /// Protocol version, always 1.
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Device identifier that authored this op.
    pub device_id: Id32,
    /// Monotonically increasing sequence number in this device lane.
    pub lane_seq: u64,
    /// Identifier of the prior op in this device lane (None for first op).
    pub lane_prev: Option<Id32>,
    /// Hybrid logical clock timestamp `[wall_ms, counter]`.
    pub hlc: Hlc,
    /// Operation kind.
    pub kind: OpKind,
    /// Target object identifier (16 bytes).
    pub object_id: Id16,
    /// Note Key wrapped under Vault Key.
    pub nk_wrap: Option<Vec<u8>>,
    /// 24-byte nonce for AEAD content encryption.
    pub nonce: [u8; 24],
    /// Causal dependencies.
    pub deps: Vec<Id32>,
    /// Padded, AEAD-encrypted payload ciphertext.
    pub ct: Vec<u8>,
    /// Classical device signature (Ed25519) over `OpHeader`.
    #[serde(with = "serde_sig64")]
    pub sig_ed: [u8; 64],
    /// Post-quantum device signature (ML-DSA-65) over `OpHeader`.
    pub sig_pq: Vec<u8>,
}

impl Op {
    /// Constructs the `OpHeader` from this `Op`.
    #[must_use]
    pub fn to_header(&self) -> OpHeader {
        OpHeader {
            v: self.v,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq: self.lane_seq,
            lane_prev: self.lane_prev,
            hlc: self.hlc,
            kind: self.kind,
            object_id: self.object_id,
            nk_wrap: self.nk_wrap.clone(),
            nonce: self.nonce,
            deps: self.deps.clone(),
            ct_hash: compute_ct_hash(&self.ct),
        }
    }

    /// Computes the unique `op_id` for this operation:
    /// `SHA-256("tn/v1/op-id" || canonical_cbor(OpHeader))`
    ///
    /// # Errors
    /// Returns `TnError::EncodingError` if canonical CBOR serialization fails.
    pub fn compute_op_id(&self) -> Result<Id32, TnError> {
        let header = self.to_header();
        compute_op_id(&header)
    }

    /// Encodes this `Op` into strict canonical CBOR.
    ///
    /// # Errors
    /// Returns `TnError::EncodingError` if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TnError> {
        cbor::encode_canonical(self)
    }

    /// Decodes an `Op` from strict canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `TnError::EncodingError` if decoding or strict validation fails.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TnError> {
        cbor::decode_canonical(bytes)
    }
}

/// Computes `ct_hash = SHA-256(ct)`.
#[must_use]
pub fn compute_ct_hash(ct: &[u8]) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(ct);
    let hash: [u8; 32] = hasher.finalize().into();
    Id32::from_bytes(hash)
}

/// Computes `op_id = SHA-256("tn/v1/op-id" || canonical_cbor(header))`.
///
/// # Errors
/// Returns `TnError::EncodingError` if canonical serialization fails.
pub fn compute_op_id(header: &OpHeader) -> Result<Id32, TnError> {
    let header_bytes = cbor::encode_canonical(header)?;
    let mut hasher = Sha256::new();
    hasher.update(LABEL_OP_ID.as_bytes());
    hasher.update(&header_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(Id32::from_bytes(hash))
}

/// Structure used for calculating AEAD Associated Data for payload encryption:
/// AAD = `LABEL_AEAD_OP || canonical_cbor({ v, account_id, device_id, lane_seq, object_id, kind })`
#[derive(Serialize)]
struct AadData {
    v: u32,
    account_id: Id32,
    device_id: Id32,
    lane_seq: u64,
    object_id: Id16,
    kind: OpKind,
}

/// Computes the exact AEAD Associated Data byte array for note payload encryption.
///
/// # Errors
/// Returns `TnError::EncodingError` if CBOR encoding fails.
pub fn compute_op_aad(
    v: u32,
    account_id: Id32,
    device_id: Id32,
    lane_seq: u64,
    object_id: Id16,
    kind: OpKind,
) -> Result<Vec<u8>, TnError> {
    let data = AadData {
        v,
        account_id,
        device_id,
        lane_seq,
        object_id,
        kind,
    };
    let cbor_bytes = cbor::encode_canonical(&data)?;
    let mut out = Vec::with_capacity(LABEL_AEAD_OP.len() + cbor_bytes.len());
    out.extend_from_slice(LABEL_AEAD_OP.as_bytes());
    out.extend_from_slice(&cbor_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_roundtrip_cbor() {
        let op = Op {
            v: 1,
            account_id: Id32::from_bytes([1u8; 32]),
            device_id: Id32::from_bytes([2u8; 32]),
            lane_seq: 0,
            lane_prev: None,
            hlc: Hlc::new(1_700_000_000_000, 0),
            kind: OpKind::Put,
            object_id: Id16::from_bytes([3u8; 16]),
            nk_wrap: Some(vec![0xAA; 72]),
            nonce: [0x55; 24],
            deps: vec![],
            ct: vec![0x11, 0x22, 0x33],
            sig_ed: [0xEE; 64],
            sig_pq: vec![0xDD; 100],
        };

        let bytes = op.to_cbor().unwrap();
        let decoded = Op::from_cbor(&bytes).unwrap();
        assert_eq!(op, decoded);

        let op_id = op.compute_op_id().unwrap();
        assert_ne!(op_id.as_bytes(), &[0u8; 32]);
    }
}
