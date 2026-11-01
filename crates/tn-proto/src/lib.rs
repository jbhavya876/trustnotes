#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::doc_markdown)]
//! `tn-proto`: Wire protocol types, request-signing scheme, and server receipts.
//!
//! Implements:
//! - [`AuthHeaders`]: `X-TN-*` request authentication scheme with anti-replay and skew checks.
//! - [`Receipt`]: Server-signed receipt committing an op to an account tree position with merge deadline.
//! - Request & response payloads for all `/v1/` HTTP endpoints (SPEC §6).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tn_crypto::labels::{LABEL_DEVICE_CERT, LABEL_GOSSIP_SIG};
use tn_crypto::{derive_device_id, HybridSignature, SigningKeys, VerifyingKeys};
use tn_oplog::Op;
use tn_types::{cbor, Id32, TnError};

pub mod evidence;
pub use evidence::{
    BundleEvidence, EquivocationEvidence, EvidenceBundle, EvidenceKind, MergeDeadlineEvidence,
    SplitViewEvidence,
};

pub mod release;
pub use release::{
    verify_binary_authenticity, BuilderAttestation, ReleaseEntry, ReleaseLog, ReleaseLogManifest,
};

/// Maximum allowed clock skew in milliseconds (60 seconds per SPEC §6.1).
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Maximum number of ops accepted in a single batch submission (SPEC §6).
pub const MAX_OPS_PER_BATCH: usize = 64;

// ─── Request Authentication (X-TN-* Scheme) ───────────────────────────────────

/// Authentication headers for request signing (`X-TN-*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthHeaders {
    /// Device identifier (32-byte public key hash).
    pub device_id: Id32,
    /// 16-byte random single-use nonce (hex in HTTP header).
    pub nonce: [u8; 16],
    /// Client timestamp (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Hybrid signature (Ed25519 + ML-DSA-65) over canonical request envelope.
    pub signature: HybridSignature,
}

/// Request envelope hashed for signing.
#[derive(Debug, Serialize, Deserialize)]
struct RequestEnvelope<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    body_hash: [u8; 32],
    nonce: [u8; 16],
    timestamp_ms: u64,
    server_origin: &'a str,
}

/// Computes SHA-256 hash of a request body.
#[must_use]
pub fn compute_body_hash(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(body);
    h.finalize().into()
}

/// Signs an HTTP request using the device's hybrid signing keys.
///
/// # Errors
/// Returns `TnError::Decode` if canonical CBOR encoding of the envelope fails.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    device_id: Id32,
    device_keys: &SigningKeys,
    nonce: [u8; 16],
    timestamp_ms: u64,
    server_origin: &str,
) -> Result<AuthHeaders, TnError> {
    let body_hash = compute_body_hash(body);
    let envelope = RequestEnvelope {
        method,
        path,
        query,
        body_hash,
        nonce,
        timestamp_ms,
        server_origin,
    };
    let canonical_bytes = cbor::encode_canonical(&envelope)?;
    let signature = device_keys.sign(&canonical_bytes);

    Ok(AuthHeaders {
        device_id,
        nonce,
        timestamp_ms,
        signature,
    })
}

/// Verifies an HTTP request against the sender device's verifying keys.
///
/// # Errors
/// - `TnError::OrderViolation` if client clock skew exceeds 60 seconds.
/// - `TnError::BadSignature` if either signature fails or body hash does not match.
#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    headers: &AuthHeaders,
    device_verifying_keys: &VerifyingKeys,
    server_now_ms: u64,
    server_origin: &str,
) -> Result<(), TnError> {
    // 1. Clock skew check (|client - server| <= 60s)
    let skew = headers.timestamp_ms.abs_diff(server_now_ms);
    if skew > MAX_CLOCK_SKEW_MS {
        return Err(TnError::OrderViolation);
    }

    // 2. Reconstruct envelope and canonical bytes
    let body_hash = compute_body_hash(body);
    let envelope = RequestEnvelope {
        method,
        path,
        query,
        body_hash,
        nonce: headers.nonce,
        timestamp_ms: headers.timestamp_ms,
        server_origin,
    };
    let canonical_bytes = cbor::encode_canonical(&envelope)?;

    // 3. Verify hybrid signature (AND rule)
    device_verifying_keys.verify(&canonical_bytes, &headers.signature)
}

// ─── Server Receipts (SPEC §3) ────────────────────────────────────────────────

/// Context label for server receipt hybrid signatures.
pub const LABEL_RECEIPT_SIG: &str = "tn/v1/receipt/sig";

/// Receipt issued by the sequencer upon accepting an operation.
///
/// Represents an accountable promise: if the op is not provably published in
/// a witnessed global checkpoint by `mmd_epoch`, this receipt constitutes
/// cryptographic proof of server omission (Scenario S10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Protocol version (1).
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Operation identifier.
    pub op_id: Id32,
    /// 0-based index assigned in the per-account Merkle tree.
    pub index: u64,
    /// Size of the account Merkle tree immediately after appending this op.
    pub account_tree_size_after: u64,
    /// Server timestamp when the receipt was created (Unix ms).
    pub server_time: u64,
    /// Maximum Merge Delay: target epoch by which this op must be published.
    pub mmd_epoch: u64,
    /// Server Ed25519 signature over canonical receipt fields.
    #[serde(with = "tn_types::serde_bytes_64")]
    pub sig_ed: [u8; 64],
    /// Server ML-DSA-65 signature over canonical receipt fields.
    pub sig_pq: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ReceiptEnvelope {
    v: u32,
    account_id: Id32,
    op_id: Id32,
    index: u64,
    account_tree_size_after: u64,
    server_time: u64,
    mmd_epoch: u64,
}

impl Receipt {
    /// Computes canonical signed bytes for this receipt.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, TnError> {
        let env = ReceiptEnvelope {
            v: self.v,
            account_id: self.account_id,
            op_id: self.op_id,
            index: self.index,
            account_tree_size_after: self.account_tree_size_after,
            server_time: self.server_time,
            mmd_epoch: self.mmd_epoch,
        };
        let cbor_bytes = cbor::encode_canonical(&env)?;
        let mut msg = Vec::with_capacity(LABEL_RECEIPT_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_RECEIPT_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);
        Ok(msg)
    }

    /// Verifies the server's hybrid signature over this receipt.
    pub fn verify(&self, server_verifying_keys: &VerifyingKeys) -> Result<(), TnError> {
        let msg = self.signed_bytes()?;
        let sig = HybridSignature {
            ed25519: self.sig_ed,
            ml_dsa: self.sig_pq.clone(),
        };
        server_verifying_keys.verify(&msg, &sig)
    }

    /// Issues and signs a new Receipt using server signing keys.
    ///
    /// # Errors
    /// Returns `TnError` if serialization fails.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        account_id: Id32,
        op_id: Id32,
        index: u64,
        account_tree_size_after: u64,
        server_time: u64,
        mmd_epoch: u64,
        server_keys: &SigningKeys,
    ) -> Result<Self, TnError> {
        let env = ReceiptEnvelope {
            v: 1,
            account_id,
            op_id,
            index,
            account_tree_size_after,
            server_time,
            mmd_epoch,
        };
        let cbor_bytes = cbor::encode_canonical(&env)?;
        let mut msg = Vec::with_capacity(LABEL_RECEIPT_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_RECEIPT_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let sig = server_keys.sign(&msg);

        Ok(Self {
            v: 1,
            account_id,
            op_id,
            index,
            account_tree_size_after,
            server_time,
            mmd_epoch,
            sig_ed: sig.ed25519,
            sig_pq: sig.ml_dsa,
        })
    }
}

// ─── API Request and Response Types (/v1/) ────────────────────────────────────

/// Request payload for `POST /v1/ops` (SPEC §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpSubmitReq {
    /// Batch of operations to sequence (max 64).
    pub ops: Vec<Op>,
    /// Whether signed receipts are requested for each accepted op.
    pub receipt_requested: bool,
}

/// Response payload for `POST /v1/ops`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpSubmitResp {
    /// Number of operations successfully sequenced.
    pub accepted: u32,
    /// Signed receipts for the sequenced ops.
    pub receipts: Vec<Receipt>,
}

/// Response payload for `GET /v1/ops?after=&limit=`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpFetchResp {
    /// Fetched operations paired with their 0-based account tree indices.
    pub ops: Vec<(Op, u64)>,
    /// Current total size of the account Merkle tree.
    pub account_tree_size: u64,
}

/// Response payload for `GET /v1/account/head`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountHeadResp {
    /// Target account ID.
    pub account_id: Id32,
    /// Total number of operations committed in the account tree.
    pub tree_size: u64,
    /// Current Merkle root hash of the account tree.
    pub root_hash: [u8; 32],
}

/// Response payload for `GET /v1/account/proof/inclusion?index=`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResp {
    /// Leaf index for which this proof was generated.
    pub leaf_index: u64,
    /// Account tree size at the time of proof generation.
    pub tree_size: u64,
    /// RFC 9162 sibling path.
    pub path: Vec<[u8; 32]>,
}

/// Response payload for `GET /v1/account/proof/consistency?from=&to=`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofResp {
    /// Prior account tree size.
    pub old_size: u64,
    /// Newer account tree size.
    pub new_size: u64,
    /// RFC 9162 consistency path.
    pub path: Vec<[u8; 32]>,
}

/// Response payload for `GET /v1/server-info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoResp {
    /// Supported protocol version (1).
    pub protocol_version: u8,
    /// Server Ed25519 identity public key.
    pub server_ed25519_pub: [u8; 32],
    /// Server ML-DSA-65 identity public key.
    pub server_mldsa65_pub: Vec<u8>,
    /// Pinned witness public key identifiers.
    pub witness_list: Vec<[u8; 32]>,
    /// Current publishing epoch number.
    pub current_epoch: u64,
    /// Default Maximum Merge Delay in epochs (10).
    pub mmd_epochs: u64,
}

/// Request payload for `POST /v1/accounts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRegisterReq {
    /// Deterministic Account ID derived from AIK public keys.
    pub account_id: Id32,
    /// Account Identity Key (Ed25519) public key.
    pub aik_ed_pub: [u8; 32],
    /// Account Identity Key (ML-DSA-65) public key.
    pub aik_pq_pub: Vec<u8>,
    /// Optional initial device enrollment operation (kind 3).
    pub initial_op: Option<Op>,
    /// Optional invite code or proof-of-work solution for sybil defense.
    pub invite_token: Option<String>,
}

/// Canonical envelope for AIK signature over a device certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertEnvelope<'a> {
    pub v: u32,
    pub account_id: Id32,
    pub device_id: Id32,
    pub dsk_ed_pub: [u8; 32],
    pub dsk_pq_pub: &'a [u8],
    pub dtk_pub: &'a [u8],
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

/// Device authorization certificate cross-signed by the Account Identity Key (AIK).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    /// Protocol version (1).
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Device identifier: SHA-256(dsk_ed_pub || dsk_pq_pub).
    pub device_id: Id32,
    /// Device Signing Key (Ed25519) public key bytes.
    pub dsk_ed_pub: [u8; 32],
    /// Device Signing Key (ML-DSA-65) public key bytes.
    pub dsk_pq_pub: Vec<u8>,
    /// Device Transport Key (X-Wing) public key bytes.
    pub dtk_pub: Vec<u8>,
    /// Certificate issuance timestamp (Unix ms).
    pub issued_at: u64,
    /// Optional expiration timestamp (Unix ms, null = perpetual).
    pub expires_at: Option<u64>,
    /// AIK-Ed25519 signature over canonical envelope.
    #[serde(with = "tn_types::serde_bytes_64")]
    pub sig_aik_ed: [u8; 64],
    /// AIK-ML-DSA-65 signature over canonical envelope.
    pub sig_aik_pq: Vec<u8>,
}

impl DeviceCertificate {
    /// Issues a new DeviceCertificate cross-signed by AIK.
    ///
    /// # Errors
    /// Returns `TnError::Decode` if canonical CBOR serialization fails.
    pub fn issue(
        account_id: Id32,
        dsk_vk: &VerifyingKeys,
        dtk_pub: Vec<u8>,
        issued_at: u64,
        expires_at: Option<u64>,
        aik_keys: &SigningKeys,
    ) -> Result<Self, TnError> {
        let device_id = derive_device_id(&dsk_vk.ed25519_bytes, &dsk_vk.mldsa65_bytes);
        let envelope = DeviceCertEnvelope {
            v: 1,
            account_id,
            device_id,
            dsk_ed_pub: dsk_vk.ed25519_bytes,
            dsk_pq_pub: &dsk_vk.mldsa65_bytes,
            dtk_pub: &dtk_pub,
            issued_at,
            expires_at,
        };
        let cbor_bytes = cbor::encode_canonical(&envelope)?;
        let mut msg = Vec::with_capacity(LABEL_DEVICE_CERT.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_DEVICE_CERT.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let sig = aik_keys.sign(&msg);

        Ok(Self {
            v: 1,
            account_id,
            device_id,
            dsk_ed_pub: dsk_vk.ed25519_bytes,
            dsk_pq_pub: dsk_vk.mldsa65_bytes.clone(),
            dtk_pub,
            issued_at,
            expires_at,
            sig_aik_ed: sig.ed25519,
            sig_aik_pq: sig.ml_dsa,
        })
    }

    /// Verifies the certificate against AIK verifying keys.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` if device_id or AIK hybrid signature is invalid.
    pub fn verify(&self, aik_vk: &VerifyingKeys) -> Result<(), TnError> {
        let derived_id = derive_device_id(&self.dsk_ed_pub, &self.dsk_pq_pub);
        if derived_id != self.device_id {
            return Err(TnError::BadSignature);
        }

        let envelope = DeviceCertEnvelope {
            v: self.v,
            account_id: self.account_id,
            device_id: self.device_id,
            dsk_ed_pub: self.dsk_ed_pub,
            dsk_pq_pub: &self.dsk_pq_pub,
            dtk_pub: &self.dtk_pub,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        let cbor_bytes = cbor::encode_canonical(&envelope)?;
        let mut msg = Vec::with_capacity(LABEL_DEVICE_CERT.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_DEVICE_CERT.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let hybrid_sig = HybridSignature {
            ed25519: self.sig_aik_ed,
            ml_dsa: self.sig_aik_pq.clone(),
        };

        aik_vk.verify(&msg, &hybrid_sig)
    }

    /// Accessor for device verifying keys.
    #[must_use]
    pub fn device_verifying_keys(&self) -> VerifyingKeys {
        VerifyingKeys {
            ed25519_bytes: self.dsk_ed_pub,
            mldsa65_bytes: self.dsk_pq_pub.clone(),
        }
    }
}

/// Payload for `device-revoke` (kind 4) operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevokePayload {
    /// Protocol version (1).
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Target device identifier being revoked.
    pub target_device_id: Id32,
    /// Timestamp of revocation (Unix ms).
    pub revoked_at: u64,
    /// Optional revocation reason string.
    pub reason: Option<String>,
}

/// Payload envelope for device gossip messages.
#[derive(Debug, Serialize, Deserialize)]
struct DeviceGossipEnvelope {
    v: u32,
    account_id: Id32,
    device_id: Id32,
    tree_size: u64,
    root_hash: [u8; 32],
    checkpoint_size: u64,
    checkpoint_root: [u8; 32],
    timestamp_ms: u64,
}

/// Device gossip message for peer-to-peer split-view detection (SPEC §5, Claim C4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGossip {
    /// Protocol version (1).
    pub v: u32,
    /// Account identifier.
    pub account_id: Id32,
    /// Reporting device identifier.
    pub device_id: Id32,
    /// Observed account tree size.
    pub tree_size: u64,
    /// Observed account Merkle root hash.
    pub root_hash: [u8; 32],
    /// Observed global checkpoint log size.
    pub checkpoint_size: u64,
    /// Observed global checkpoint root hash.
    pub checkpoint_root: [u8; 32],
    /// Timestamp when gossip was signed (Unix ms).
    pub timestamp_ms: u64,
    /// Ed25519 signature over canonical gossip envelope.
    #[serde(with = "tn_types::serde_bytes_64")]
    pub sig_ed: [u8; 64],
    /// ML-DSA-65 signature over canonical gossip envelope.
    pub sig_pq: Vec<u8>,
}

impl DeviceGossip {
    /// Creates and signs a new device gossip message.
    ///
    /// # Errors
    /// Returns `TnError` if serialization fails.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        account_id: Id32,
        device_id: Id32,
        tree_size: u64,
        root_hash: [u8; 32],
        checkpoint_size: u64,
        checkpoint_root: [u8; 32],
        timestamp_ms: u64,
        signing_keys: &SigningKeys,
    ) -> Result<Self, TnError> {
        let envelope = DeviceGossipEnvelope {
            v: 1,
            account_id,
            device_id,
            tree_size,
            root_hash,
            checkpoint_size,
            checkpoint_root,
            timestamp_ms,
        };
        let cbor_bytes = cbor::encode_canonical(&envelope)?;
        let mut msg = Vec::with_capacity(LABEL_GOSSIP_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_GOSSIP_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let hybrid_sig = signing_keys.sign(&msg);

        Ok(Self {
            v: 1,
            account_id,
            device_id,
            tree_size,
            root_hash,
            checkpoint_size,
            checkpoint_root,
            timestamp_ms,
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        })
    }

    /// Verifies device gossip signature against reporting device's verifying keys.
    ///
    /// # Errors
    /// Returns `TnError::BadSignature` if signature is invalid.
    pub fn verify(&self, device_vk: &VerifyingKeys) -> Result<(), TnError> {
        let envelope = DeviceGossipEnvelope {
            v: self.v,
            account_id: self.account_id,
            device_id: self.device_id,
            tree_size: self.tree_size,
            root_hash: self.root_hash,
            checkpoint_size: self.checkpoint_size,
            checkpoint_root: self.checkpoint_root,
            timestamp_ms: self.timestamp_ms,
        };
        let cbor_bytes = cbor::encode_canonical(&envelope)?;
        let mut msg = Vec::with_capacity(LABEL_GOSSIP_SIG.len() + cbor_bytes.len());
        msg.extend_from_slice(LABEL_GOSSIP_SIG.as_bytes());
        msg.extend_from_slice(&cbor_bytes);

        let hybrid_sig = HybridSignature {
            ed25519: self.sig_ed,
            ml_dsa: self.sig_pq.clone(),
        };

        device_vk.verify(&msg, &hybrid_sig)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_keys() -> (SigningKeys, VerifyingKeys) {
        let sk = SigningKeys::generate().unwrap();
        let vk = sk.verifying_keys();
        (sk, vk)
    }

    #[test]
    fn test_sign_and_verify_request_happy_path() {
        let (sk, vk) = make_test_keys();
        let device_id = Id32::from_bytes([0x42; 32]);
        let now_ms = 1_700_000_000_000u64;
        let nonce = [0xAA; 16];
        let origin = "trustnotes.alterblock.com";

        let body = b"{\"action\":\"test_body\"}";

        let headers = sign_request(
            "POST",
            "/v1/ops",
            "receipt=true",
            body,
            device_id,
            &sk,
            nonce,
            now_ms,
            origin,
        )
        .unwrap();

        let verify_result = verify_request(
            "POST",
            "/v1/ops",
            "receipt=true",
            body,
            &headers,
            &vk,
            now_ms + 1000, // 1s server delta (within 60s)
            origin,
        );
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_verify_request_skew_exceeded_fails() {
        let (sk, vk) = make_test_keys();
        let device_id = Id32::from_bytes([0x42; 32]);
        let now_ms = 1_700_000_000_000u64;
        let nonce = [0xAA; 16];
        let origin = "trustnotes.alterblock.com";
        let body = b"test";

        let headers = sign_request(
            "POST", "/v1/ops", "", body, device_id, &sk, nonce, now_ms, origin,
        )
        .unwrap();

        // Server time is 61 seconds ahead (> 60_000ms max skew)
        let verify_result = verify_request(
            "POST",
            "/v1/ops",
            "",
            body,
            &headers,
            &vk,
            now_ms + 61_000,
            origin,
        );
        assert!(matches!(verify_result, Err(TnError::OrderViolation)));
    }

    #[test]
    fn test_verify_request_tampered_body_fails() {
        let (sk, vk) = make_test_keys();
        let device_id = Id32::from_bytes([0x42; 32]);
        let now_ms = 1_700_000_000_000u64;
        let nonce = [0xAA; 16];
        let origin = "trustnotes.alterblock.com";

        let headers = sign_request(
            "POST",
            "/v1/ops",
            "",
            b"authentic body",
            device_id,
            &sk,
            nonce,
            now_ms,
            origin,
        )
        .unwrap();

        let verify_result = verify_request(
            "POST",
            "/v1/ops",
            "",
            b"tampered body",
            &headers,
            &vk,
            now_ms,
            origin,
        );
        assert!(matches!(verify_result, Err(TnError::BadSignature)));
    }

    #[test]
    fn test_receipt_sign_and_verify() {
        let (server_sk, server_vk) = make_test_keys();
        let mut receipt = Receipt {
            v: 1,
            account_id: Id32::from_bytes([1u8; 32]),
            op_id: Id32::from_bytes([2u8; 32]),
            index: 0,
            account_tree_size_after: 1,
            server_time: 1_700_000_000_000,
            mmd_epoch: 10,
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        };

        let msg = receipt.signed_bytes().unwrap();
        let sig = server_sk.sign(&msg);
        receipt.sig_ed = sig.ed25519;
        receipt.sig_pq = sig.ml_dsa;

        assert!(receipt.verify(&server_vk).is_ok());

        // Tamper with receipt index
        let mut tampered = receipt.clone();
        tampered.index = 999;
        assert!(matches!(
            tampered.verify(&server_vk),
            Err(TnError::BadSignature)
        ));
    }

    #[test]
    fn test_device_certificate_issue_verify_and_tamper() {
        let (aik_sk, aik_vk) = make_test_keys();
        let (_dsk_sk, dsk_vk) = make_test_keys();
        let account_id = Id32::from_bytes([0x12; 32]);
        let dtk_pub = vec![0x33; 32];
        let now_ms = 1_700_000_000_000u64;

        let cert =
            DeviceCertificate::issue(account_id, &dsk_vk, dtk_pub, now_ms, None, &aik_sk).unwrap();

        assert_eq!(
            cert.device_id,
            derive_device_id(&dsk_vk.ed25519_bytes, &dsk_vk.mldsa65_bytes)
        );
        assert!(cert.verify(&aik_vk).is_ok());

        // Tamper with cert account_id
        let mut tampered = cert.clone();
        tampered.account_id = Id32::from_bytes([0x99; 32]);
        assert!(matches!(
            tampered.verify(&aik_vk),
            Err(TnError::BadSignature)
        ));

        // Verification with wrong AIK fails
        let (_, wrong_aik_vk) = make_test_keys();
        assert!(matches!(
            cert.verify(&wrong_aik_vk),
            Err(TnError::BadSignature)
        ));
    }
}
