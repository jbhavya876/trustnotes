#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-proto`: Wire protocol types and request-signing scheme.
//!
//! Defines the HTTP API request and response structures, CBOR serialization helpers,
//! and the `X-TN-*` header authentication pipeline used between client and server.
//!
//! # M0 Status
//!
//! Skeleton crate. Wire types and authentication headers land in M2.

use tn_types::TnError;

/// Authentication headers for request signing (`X-TN-*`).
#[derive(Debug, Clone)]
pub struct AuthHeaders {
    /// Device identifier (32-byte hex or bytes).
    pub device_id: [u8; 32],
    /// 16-byte random single-use nonce.
    pub nonce: [u8; 16],
    /// Client timestamp (Unix milliseconds). Skew > 60s rejected.
    pub timestamp_ms: u64,
    /// Ed25519 signature over canonical request fields.
    pub sig_ed: [u8; 64],
    /// Post-quantum ML-DSA-65 signature over canonical request fields.
    pub sig_pq: Vec<u8>,
}

/// Verify request authentication headers against a known device public key.
///
/// # Errors
///
/// Returns [`TnError::BadSignature`] if signatures are invalid.
/// Returns [`TnError::Internal`] until M2.
pub fn verify_request_auth(
    _method: &str,
    _path: &str,
    _body_hash: &[u8; 32],
    _headers: &AuthHeaders,
) -> Result<(), TnError> {
    Err(TnError::Internal("not implemented — M2".to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_m0() {
        assert_eq!(1 + 1, 2);
    }
}
