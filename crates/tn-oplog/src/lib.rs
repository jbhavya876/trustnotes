#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-oplog`: Account operation log — the append-only, CRDT-structured operation journal.
//!
//! Each account maintains a per-device op log that is authenticated, sequenced,
//! and eventually merged into a total-order account tree by the server.
//!
//! # M0 Status
//!
//! Skeleton crate. All types and functions will be implemented in M1.
//!
//! # Key Concepts (M1+)
//!
//! - **Op**: A single authenticated, CBOR-encoded operation (`Put`, `Delete`, `DeviceAdd`, etc.).
//! - **Lane**: A per-device totally-ordered sub-log identified by `device_id`.
//! - **Account Tree**: A Merkle tree over all lanes, updated per epoch.
//! - **`lane_seq`**: Monotonically increasing per-lane sequence number.
//! - **leaf position**: The op's position in the global account tree leaf array.

/// Placeholder module — fully implemented in M1.
pub mod oplog {
    use tn_types::TnError;

    /// An operation in the account log.
    ///
    /// Full definition (with CBOR encoding, signatures, `ct_hash`, etc.) lands in M1.
    pub struct Op {
        /// Placeholder field to keep the struct non-empty.
        _placeholder: (),
    }

    /// Append an op to the in-memory lane buffer.
    ///
    /// # Errors
    ///
    /// Returns [`TnError::Internal`] until M1.
    pub fn append(_op: Op) -> Result<(), TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_m0() {
        assert_eq!(1 + 1, 2);
    }
}
