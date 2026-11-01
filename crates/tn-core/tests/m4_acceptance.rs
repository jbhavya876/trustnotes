#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Acceptance test suite for Module M4 (Transparency Pipeline, Witness Network & Verification).
//!
//! Enforces:
//! - Full transparency pipeline: Server -> 2-of-3 Witness cosignatures -> Client verification (ADR-0001).
//! - Bitcoin OpenTimestamps offline verification (Claim C6, SPEC §4).
//! - Release transparency log and binary self-verification (Claim C7, SPEC §4).
//! - Accountable promises, missed merge deadline detection & evidence bundles (Claim C5, Scenario S10).
//! - Third-party monitor auditor invariant enforcement & equivocation detection (Claim C10, Scenario S12).

use tempfile::tempdir;
use tn_core::{
    sync::{SyncClient, SyncTransport},
    vault::Vault,
};
use tn_crypto::{SigningKeys, VerifyingKeys};
use tn_monitor::MonitorAuditor;
use tn_proto::{
    evidence::{EvidenceBundle, EvidenceKind},
    release::{verify_binary_authenticity, BuilderAttestation, ReleaseEntry, ReleaseLog},
    AccountHeadResp, AccountRegisterReq, AuthHeaders, ConsistencyProofResp, OpFetchResp,
    OpSubmitReq, OpSubmitResp,
};
use tn_server::Server;
use tn_tlog::{
    ots::{create_mock_ots_proof, verify_ots_proof},
    Checkpoint, Cosignature, WitnessPolicy,
};
use tn_types::{Id32, TnError};

/// In-memory transport adapter for testing transparency pipeline against a server.
struct TransparencyTestTransport<'a> {
    server: &'a mut Server,
    device_vk: VerifyingKeys,
    now_ms: u64,
    forged_head: Option<AccountHeadResp>,
}

impl<'a> TransparencyTestTransport<'a> {
    fn new(server: &'a mut Server, device_vk: VerifyingKeys, now_ms: u64) -> Self {
        Self {
            server,
            device_vk,
            now_ms,
            forged_head: None,
        }
    }
}

impl<'a> SyncTransport for TransparencyTestTransport<'a> {
    fn submit_ops(
        &mut self,
        req: &OpSubmitReq,
        headers: &AuthHeaders,
    ) -> Result<OpSubmitResp, TnError> {
        self.server
            .submit_ops(req, headers, &self.device_vk, self.now_ms)
    }

    fn fetch_ops(
        &self,
        account_id: &Id32,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<OpFetchResp, TnError> {
        self.server.fetch_ops(account_id, after_index, limit)
    }

    fn get_account_head(&self, account_id: &Id32) -> Result<AccountHeadResp, TnError> {
        if let Some(h) = &self.forged_head {
            return Ok(h.clone());
        }
        self.server.get_account_head(account_id)
    }

    fn get_account_consistency_proof(
        &self,
        account_id: &Id32,
        from_size: u64,
    ) -> Result<ConsistencyProofResp, TnError> {
        self.server
            .get_account_consistency_proof(account_id, from_size)
    }

    fn get_checkpoint(&self) -> Result<Checkpoint, TnError> {
        self.server
            .get_checkpoint()
            .cloned()
            .ok_or(TnError::Unavailable)
    }
}

fn setup_transparency_env() -> (Server, WitnessPolicy, [u8; 32], [u8; 32], [u8; 32]) {
    let server = Server::in_memory("trustnotes.org/log/test".to_string()).unwrap();
    let w1 = [0x11u8; 32];
    let w2 = [0x22u8; 32];
    let w3 = [0x33u8; 32];
    let policy = WitnessPolicy {
        threshold: 2,
        pinned_witnesses: vec![w1, w2, w3],
        max_age_seconds: 600,
    };
    (server, policy, w1, w2, w3)
}

/// Test 1: Full transparency pipeline: Server -> 2-of-3 Witness cosignatures -> Client verification.
#[test]
fn test_m4_transparency_pipeline_witness_network() {
    let (mut server, policy, w1, w2, _) = setup_transparency_env();
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let (mut vault, phrase) = Vault::create_new(&db_path, Some("m4-pass")).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 24);

    let dev_vk = vault.signing_keys_ref().verifying_keys();
    let now_ms = 1_700_000_000_000u64;

    // Register account
    let reg_req = AccountRegisterReq {
        account_id: vault.account_id(),
        aik_ed_pub: dev_vk.ed25519_bytes,
        aik_pq_pub: dev_vk.mldsa65_bytes.clone(),
        initial_op: None,
        invite_token: None,
    };
    server.register_account(&reg_req, now_ms).unwrap();

    // Create a note
    let _ = vault
        .new_note(
            "Module 4 Note",
            "Transparency log testing",
            vec!["m4".into()],
            None,
        )
        .unwrap();

    let mut client = SyncClient::new(
        "trustnotes.org/log/test".to_string(),
        server.verifying_keys(),
        policy,
    );

    // 1. Push ops to server
    {
        let mut transport = TransparencyTestTransport::new(&mut server, dev_vk.clone(), now_ms);
        let receipts = client.push_ops(&vault, &mut transport, now_ms).unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].verify(&server.verifying_keys()).is_ok());
    }

    // 2. Server publishes checkpoint at epoch 1
    let mut cp = server.publish_epoch(now_ms + 100).unwrap();
    assert_eq!(cp.size, 1);

    // 3. Independent witnesses W1 and W2 cosign the checkpoint
    cp.cosignatures.push(Cosignature {
        witness_key_id: w1,
        timestamp_ms: now_ms + 100,
        sig_ed: [0u8; 64],
    });
    cp.cosignatures.push(Cosignature {
        witness_key_id: w2,
        timestamp_ms: now_ms + 100,
        sig_ed: [0u8; 64],
    });
    server.set_latest_checkpoint(cp);

    // 4. Client pulls and verifies checkpoint, 2-of-3 threshold, and consistency
    let transport = TransparencyTestTransport::new(&mut server, dev_vk, now_ms + 200);
    let report = client
        .pull_and_verify(&mut vault, &transport, now_ms + 200)
        .unwrap();

    assert_eq!(report.checkpoint_log_size, 1);
    assert_eq!(report.ops_pulled, 0); // Local device authored the op

    // Verify local invariants hold
    let local_verify = vault.verify_local().unwrap();
    assert!(local_verify.valid);
}

/// Test 2: Bitcoin OpenTimestamps offline verification (Claim C6).
#[test]
fn test_m4_bitcoin_ots_time_evidence_verification() {
    let cp_root = [0x7Au8; 32];
    let block_height = 860_000;
    let block_time = 1_725_000_000;

    let (proof, block_hash) = create_mock_ots_proof(&cp_root, block_height, block_time);

    // 1. Successful offline verification
    let res = verify_ots_proof(&cp_root, &proof, &block_hash).unwrap();
    assert_eq!(res.block_height, block_height);
    assert_eq!(res.block_hash, block_hash);
    assert_eq!(res.block_timestamp, block_time);

    // 2. Tampered checkpoint root MUST fail with RootMismatch
    let tampered_root = [0xFFu8; 32];
    let err_root = verify_ots_proof(&tampered_root, &proof, &block_hash).unwrap_err();
    assert!(matches!(err_root, TnError::RootMismatch));

    // 3. Tampered block hash MUST fail with CiphertextTampered
    let tampered_hash = [0xEEu8; 32];
    let err_hash = verify_ots_proof(&cp_root, &proof, &tampered_hash).unwrap_err();
    assert!(matches!(err_hash, TnError::CiphertextTampered));
}

/// Test 3: Release transparency log and reproducible binary self-verification (Claim C7).
#[test]
fn test_m4_release_transparency_and_binary_self_verification() {
    use sha2::{Digest, Sha256};

    // 1. Simulated compiled binary
    let binary_bytes = b"TrustNotes-v0.1.0-reproducible-production-binary-x86_64";
    let binary_hash: [u8; 32] = Sha256::digest(binary_bytes).into();
    let version = "0.1.0";
    let target = "x86_64-pc-windows-msvc";
    let build_time = 1_700_000_000_000u64;

    // 2. Two independent builders sign attestations
    let builder1_sk = SigningKeys::generate().unwrap();
    let builder1_vk = builder1_sk.verifying_keys();

    let builder2_sk = SigningKeys::generate().unwrap();
    let builder2_vk = builder2_sk.verifying_keys();

    let attestation1 =
        BuilderAttestation::sign(version, target, binary_hash, build_time, &builder1_sk).unwrap();
    let attestation2 =
        BuilderAttestation::sign(version, target, binary_hash, build_time, &builder2_sk).unwrap();

    // 3. Construct release entry and append to release log
    let release_entry = ReleaseEntry {
        version: version.to_string(),
        target: target.to_string(),
        binary_hash,
        attestations: vec![attestation1, attestation2],
    };

    let mut release_log = ReleaseLog::new();
    let entry_idx = release_log.append_entry(release_entry.clone());
    let proof = release_log.inclusion_proof(entry_idx).unwrap();
    let release_root = release_log.root();

    // 4. Verify binary authenticity (all checks pass)
    let trusted_builders = vec![builder1_vk, builder2_vk];
    let verify_res = verify_binary_authenticity(
        binary_bytes,
        version,
        target,
        &release_entry,
        &proof,
        &release_root,
        &trusted_builders,
        2,
    );
    assert!(verify_res.is_ok());

    // 5. Tampered binary byte MUST fail
    let mut tampered_bytes = binary_bytes.to_vec();
    tampered_bytes[0] ^= 0xFF;
    let err_tamper = verify_binary_authenticity(
        &tampered_bytes,
        version,
        target,
        &release_entry,
        &proof,
        &release_root,
        &trusted_builders,
        2,
    )
    .unwrap_err();
    assert!(matches!(err_tamper, TnError::CiphertextTampered));
}

/// Test 4: Accountable promises, missed merge deadline & evidence bundle (Claim C5, Scenario S10).
#[test]
fn test_m4_accountable_promises_missed_merge_deadline_and_evidence_bundle() {
    let (mut server, policy, w1, w2, _) = setup_transparency_env();
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create_new(&db_path, Some("m4-ev-pass")).unwrap();

    let dev_vk = vault.signing_keys_ref().verifying_keys();
    let now_ms = 1_700_000_000_000u64;

    // Register account
    let reg_req = AccountRegisterReq {
        account_id: vault.account_id(),
        aik_ed_pub: dev_vk.ed25519_bytes,
        aik_pq_pub: dev_vk.mldsa65_bytes.clone(),
        initial_op: None,
        invite_token: None,
    };
    server.register_account(&reg_req, now_ms).unwrap();

    let _ = vault
        .new_note("Deadline Note", "Testing MMD breach", vec![], None)
        .unwrap();

    let mut client = SyncClient::new(
        "trustnotes.org/log/test".to_string(),
        server.verifying_keys(),
        policy.clone(),
    );

    // Push op and receive signed receipt
    let deadline = {
        let mut transport = TransparencyTestTransport::new(&mut server, dev_vk.clone(), now_ms);
        let receipts = client.push_ops(&vault, &mut transport, now_ms).unwrap();
        assert_eq!(receipts.len(), 1);
        receipts[0].mmd_epoch
    };

    // Adversary advances checkpoints past deadline but omits op from account tree
    let mut cp = Checkpoint {
        origin: "trustnotes.org/log/test".to_string(),
        size: deadline,
        root_hash: [0x88; 32],
        timestamp_ms: now_ms + 100,
        server_sig: tn_crypto::HybridSignature {
            ed25519: [0u8; 64],
            ml_dsa: vec![],
        },
        cosignatures: vec![
            Cosignature {
                witness_key_id: w1,
                timestamp_ms: now_ms + 100,
                sig_ed: [0u8; 64],
            },
            Cosignature {
                witness_key_id: w2,
                timestamp_ms: now_ms + 100,
                sig_ed: [0u8; 64],
            },
        ],
    };
    cp.server_sig = server.signing_keys().sign(&cp.signed_body());
    server.set_latest_checkpoint(cp.clone());

    let mut transport = TransparencyTestTransport::new(&mut server, dev_vk, now_ms + 200);
    transport.forged_head = Some(AccountHeadResp {
        account_id: vault.account_id(),
        tree_size: 0,
        root_hash: [0u8; 32],
    });

    let res = client.pull_and_verify(&mut vault, &transport, now_ms + 200);
    assert!(matches!(res, Err(TnError::MergeDeadlineMissed { .. })));

    // Verify evidence bundle persisted in vault metadata
    let bundle_cbor = vault
        .get_last_evidence_bundle()
        .unwrap()
        .expect("Saved evidence bundle");
    let bundle = EvidenceBundle::from_cbor(&bundle_cbor).unwrap();
    assert_eq!(bundle.bundle_kind, EvidenceKind::MergeDeadlineMissed as u8);
    assert_eq!(bundle.account_id, vault.account_id());

    // Verify with MonitorAuditor
    let auditor = MonitorAuditor::new(
        "trustnotes.org/log/test".to_string(),
        server.verifying_keys(),
        policy,
    );
    assert!(auditor.audit_evidence_bundle(&bundle).is_ok());
}

/// Test 5: Third-party auditor monitor (`tn-monitor`) invariant enforcement (Claim C10).
#[test]
fn test_m4_monitor_auditor_end_to_end_log_audit() {
    let (server, policy, w1, w2, _) = setup_transparency_env();
    let now_ms = 1_700_000_000_000u64;

    let mut auditor = MonitorAuditor::new(
        "trustnotes.org/log/test".to_string(),
        server.verifying_keys(),
        policy,
    );

    // Initial audit of checkpoint 1
    let mut cp1 = Checkpoint {
        origin: "trustnotes.org/log/test".to_string(),
        size: 1,
        root_hash: [0x11; 32],
        timestamp_ms: now_ms,
        server_sig: tn_crypto::HybridSignature {
            ed25519: [0u8; 64],
            ml_dsa: vec![],
        },
        cosignatures: vec![
            Cosignature {
                witness_key_id: w1,
                timestamp_ms: now_ms,
                sig_ed: [0u8; 64],
            },
            Cosignature {
                witness_key_id: w2,
                timestamp_ms: now_ms,
                sig_ed: [0u8; 64],
            },
        ],
    };
    cp1.server_sig = server.signing_keys().sign(&cp1.signed_body());

    auditor.audit_checkpoint(&cp1, None, now_ms).unwrap();
    let state1 = auditor.state().unwrap();
    assert_eq!(state1.size, 1);
    assert_eq!(state1.root_hash, [0x11; 32]);

    // Checkpoint 2: equivocation test (same size 1, different root)
    let mut cp1_equiv = cp1.clone();
    cp1_equiv.root_hash = [0x99; 32];
    cp1_equiv.server_sig = server.signing_keys().sign(&cp1_equiv.signed_body());

    let equiv_err = auditor
        .audit_checkpoint(&cp1_equiv, None, now_ms)
        .unwrap_err();
    assert!(matches!(equiv_err, TnError::Equivocation { epoch: 1 }));

    // Checkpoint 3: rollback test (size 0 < 1)
    let mut cp_rollback = cp1.clone();
    cp_rollback.size = 0;
    cp_rollback.server_sig = server.signing_keys().sign(&cp_rollback.signed_body());

    let rollback_err = auditor
        .audit_checkpoint(&cp_rollback, None, now_ms)
        .unwrap_err();
    assert!(matches!(rollback_err, TnError::Rollback));
}
