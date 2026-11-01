#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]
//! `tn-types`: Shared types, IDs, canonical CBOR codec, protocol versions, and error types.
//!
//! This crate has no external dependencies at M0. It is the foundation imported by all other
//! trustnotes crates.
//!
//! # Protocol Version
//!
//! The current protocol version is [`PROTOCOL_VERSION`].
//!
//! # Error Types
//!
//! All errors in trustnotes are typed. No string-based error propagation crosses module
//! boundaries. Errors that indicate a verification failure never fall back to unverified state.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Strict deterministic CBOR encoding and decoding wrapper.
pub mod cbor;

/// Helper module for serializing and deserializing 64-byte arrays with Serde.
pub mod serde_bytes_64 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    /// Serializes a `[u8; 64]` as raw bytes.
    ///
    /// # Errors
    /// Returns serialization error if serializer fails.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    /// Deserializes a `[u8; 64]` from raw bytes.
    ///
    /// # Errors
    /// Returns deserialization error if bytes length != 64.
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

/// Current trustnotes protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Op kind discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OpKind {
    /// Create or update a note.
    Put = 1,
    /// Soft-delete a note (reversible).
    Delete = 2,
    /// Add a new device to the account.
    DeviceAdd = 3,
    /// Revoke a device from the account.
    DeviceRevoke = 4,
    /// Rotate the account root key.
    KeyRotate = 5,
    /// Crypto-shred an object (drops NK locally, asks server to purge ct).
    Shred = 6,
}

/// Errors produced by trustnotes operations.
///
/// Every variant names the exact trust boundary that was violated.
#[derive(Debug)]
#[non_exhaustive]
pub enum TnError {
    /// AEAD decryption failed or `ct_hash` mismatch. Corresponds to adversary scenario S1.
    CiphertextTampered,
    /// A gap in the account-tree position sequence was detected. Scenario S2.
    HistoryGap,
    /// Ops arrived in an order violating `lane_seq` or leaf position. Scenario S3.
    OrderViolation,
    /// A signature (Ed25519, ML-DSA-65, or hybrid) did not verify. Scenario S4.
    BadSignature,
    /// An op from a device that has been revoked was accepted. Scenario S5.
    RevokedDevice,
    /// The server returned an older or smaller account head. Scenario S6 / S9.
    Rollback,
    /// Two devices observed different histories for the same account. Scenario S7.
    SplitView,
    /// The checkpoint has fewer than k valid witness cosignatures. Scenario S8.
    WitnessPolicy,
    /// An op was receipted but not included in the log by its merge deadline. Scenario S10.
    MergeDeadlineMissed { op_id: String, deadline: u64 },
    /// An account was omitted from the epoch tree. Scenario S11.
    EpochOmission,
    /// The server published two different roots for the same epoch. Scenario S12.
    Equivocation { epoch: u64 },
    /// The checkpoint endpoint is unavailable. Client state is unchanged. Scenario S13.
    Unavailable,
    /// A Merkle proof verified against a root different from the checkpoint. Scenario S14.
    RootMismatch,
    /// CBOR decoding failed (malformed, non-canonical, or oversized). Scenario S15.
    Decode(String),
    /// The server or an incoming op uses an unsupported protocol version. Scenario S16.
    UnsupportedVersion { found: u8, expected: u8 },
    /// The server signing key changed without a log entry. Scenario S17.
    UnloggedKeyChange,
    /// An internal error not related to a security boundary.
    Internal(String),
}

impl fmt::Display for TnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextTampered => {
                write!(f, "ciphertext tampered: AEAD failure or ct_hash mismatch")
            }
            Self::HistoryGap => {
                write!(
                    f,
                    "history gap: missing op at expected account-tree position"
                )
            }
            Self::OrderViolation => {
                write!(
                    f,
                    "order violation: op lane_seq or leaf position out of sequence"
                )
            }
            Self::BadSignature => {
                write!(
                    f,
                    "bad signature: op or certificate signature verification failed"
                )
            }
            Self::RevokedDevice => {
                write!(
                    f,
                    "revoked device: op submitted after device revocation index"
                )
            }
            Self::Rollback => {
                write!(
                    f,
                    "rollback: server returned an older account head or replayed an old checkpoint"
                )
            }
            Self::SplitView => {
                write!(
                    f,
                    "split view: server served inconsistent histories to two devices"
                )
            }
            Self::WitnessPolicy => {
                write!(
                    f,
                    "witness policy not met: fewer than k valid witness cosignatures"
                )
            }
            Self::MergeDeadlineMissed { op_id, deadline } => {
                write!(
                    f,
                    "merge deadline missed: op {op_id} not included by epoch {deadline}"
                )
            }
            Self::EpochOmission => {
                write!(f, "epoch omission: account not present in epoch tree")
            }
            Self::Equivocation { epoch } => {
                write!(
                    f,
                    "equivocation: server published two roots for epoch {epoch}"
                )
            }
            Self::Unavailable => {
                write!(
                    f,
                    "checkpoint unavailable: fetch failed; local state unchanged"
                )
            }
            Self::RootMismatch => {
                write!(
                    f,
                    "root mismatch: proof root does not match checkpoint root"
                )
            }
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
            Self::UnsupportedVersion { found, expected } => {
                write!(f, "unsupported version: {found}, expected {expected}")
            }
            Self::UnloggedKeyChange => {
                write!(
                    f,
                    "unlogged key change: server signing key changed with no transparency log entry"
                )
            }
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

impl std::error::Error for TnError {}

/// A 32-byte opaque identifier (`op_id`, `account_id`, `device_id`, etc.).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Id32([u8; 32]);

impl Id32 {
    /// Create an `Id32` from a raw byte array.
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

impl fmt::Debug for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id32(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A 16-byte opaque object identifier (`object_id`, opaque to the server).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Id16([u8; 16]);

impl Id16 {
    /// Create an `Id16` from a raw byte array.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id16(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn op_kind_discriminants() {
        assert_eq!(OpKind::Put as u8, 1);
        assert_eq!(OpKind::Delete as u8, 2);
        assert_eq!(OpKind::DeviceAdd as u8, 3);
        assert_eq!(OpKind::DeviceRevoke as u8, 4);
        assert_eq!(OpKind::KeyRotate as u8, 5);
        assert_eq!(OpKind::Shred as u8, 6);
    }

    #[test]
    fn id32_roundtrip() {
        let bytes = [0xab_u8; 32];
        let id = Id32::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn id16_roundtrip() {
        let bytes = [0xcd_u8; 16];
        let id = Id16::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn error_display_ciphertext_tampered() {
        let e = TnError::CiphertextTampered;
        assert!(e.to_string().contains("ciphertext tampered"));
    }

    #[test]
    fn error_display_merge_deadline() {
        let e = TnError::MergeDeadlineMissed {
            op_id: "abc".to_string(),
            deadline: 42,
        };
        assert!(e.to_string().contains("abc"));
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn id32_display_is_hex() {
        let bytes = [0x00_u8; 32];
        let id = Id32::from_bytes(bytes);
        let s = id.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
