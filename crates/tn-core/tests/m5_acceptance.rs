#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Module M5 Acceptance Test Suite (SPEC §7, ADR-0002, Claim C8).
//!
//! Validates:
//! 1. Full Key Rotation roundtrip ($RK \to RK'$ transition, cross-signed KeyRotate op,
//!    server sequencer acceptance, and lazy note key unwrapping).
//! 2. Post-Quantum Hybrid KEM (X-Wing: X25519 + ML-KEM-768) and `EnrollmentPackage` (Claim C8).
//! 3. Local IPC Daemon lifecycle, command dispatch, and 256-bit authentication security boundary (Threat S16).
//! 4. Adversary drill: Forged or unauthorized key rotation op rejected fail-closed.

use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::tempdir;

use tn_core::ipc::{generate_auth_token, DaemonClient, DaemonServer};
use tn_core::vault::Vault;
use tn_crypto::kem::HybridKemKeyPair;
use tn_crypto::SigningKeys;
use tn_oplog::{compute_ct_hash, compute_op_id, Hlc, Op, OpHeader};
use tn_proto::{AccountRegisterReq, KeyRotatePayload, OpSubmitReq};
use tn_server::Server;
use tn_types::{Id16, OpKind, TnError};

/// 1. Full Key Rotation Roundtrip Test (ADR-0002 Mitigation 3).
#[test]
fn test_m5_full_key_rotation_roundtrip() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("vault1.db");

    // Initialize local vault
    let (mut vault, phrase1) = Vault::create_new(&db_path, Some("rotpass")).unwrap();
    let account_id = vault.account_id();
    assert_eq!(phrase1.split_whitespace().count(), 24);

    // Initialize server and register account
    let mut server = Server::in_memory("test.origin".into()).unwrap();
    let aik_vk = vault.signing_keys_ref().verifying_keys();
    let reg_req = AccountRegisterReq {
        account_id,
        aik_ed_pub: aik_vk.ed25519_bytes,
        aik_pq_pub: aik_vk.mldsa65_bytes.clone(),
        initial_op: None,
        invite_token: None,
    };
    server
        .register_account(&reg_req, 1_700_000_000_000)
        .unwrap();

    // 1. Create two notes before key rotation
    let note1_id = vault
        .new_note("Note Pre-Rotation 1", "Body 1", vec!["pre".into()], None)
        .unwrap();
    let note2_id = vault
        .new_note("Note Pre-Rotation 2", "Body 2", vec!["pre".into()], None)
        .unwrap();

    // 2. Perform master key rotation
    let now_ms = 1_700_000_100_000u64;
    let (_rotate_op, _op_id, phrase2) = vault.rotate_account_key(now_ms).unwrap();
    assert_ne!(phrase1, phrase2);
    assert_eq!(phrase2.split_whitespace().count(), 24);

    // 3. Submit all accumulated ops (note1 + note2 + key_rotate) to server sequencer
    let ops = vault.get_all_ops_internal().unwrap();
    let submit_req = OpSubmitReq {
        ops: ops.into_iter().map(|(_, op)| op).collect(),
        receipt_requested: true,
    };
    let req_bytes = tn_types::cbor::encode_canonical(&submit_req).unwrap();
    let nonce = [42u8; 16];
    let headers = tn_proto::sign_request(
        "POST",
        "/v1/ops",
        "",
        &req_bytes,
        account_id,
        vault.signing_keys_ref(),
        nonce,
        now_ms,
        "test.origin",
    )
    .unwrap();

    let submit_resp = server
        .submit_ops(&submit_req, &headers, &aik_vk, now_ms)
        .unwrap();
    assert_eq!(submit_resp.accepted, 3); // note1 + note2 + key_rotate all sequenced cleanly!

    // 4. Create a note after rotation
    let note3_id = vault
        .new_note("Note Post-Rotation 3", "Body 3", vec!["post".into()], None)
        .unwrap();

    // 5. Verify local vault integrity
    let report = vault.verify_local().unwrap();
    assert!(report.valid);
    assert_eq!(report.total_ops, 4); // note1 + note2 + key_rotate + note3

    // 6. Verify all notes (both before and after rotation) read successfully
    let n1 = vault.get_note(note1_id).unwrap();
    assert_eq!(n1.body_md, "Body 1");

    let n2 = vault.get_note(note2_id).unwrap();
    assert_eq!(n2.body_md, "Body 2");

    let n3 = vault.get_note(note3_id).unwrap();
    assert_eq!(n3.body_md, "Body 3");
}

/// 2. Post-Quantum Hybrid KEM & Enrollment Package Test (Claim C8).
#[test]
fn test_m5_post_quantum_hybrid_kem_and_enrollment_package() {
    let dir = tempdir().unwrap();
    let sender_db = dir.path().join("sender.db");
    let recipient_db = dir.path().join("recipient.db");

    let (mut sender_vault, _) = Vault::create_new(&sender_db, Some("senderpass")).unwrap();
    let sender_vk = sender_vault.signing_keys_ref().verifying_keys();

    // Generate recipient device keys (DSK and DTK)
    let recipient_dtk = HybridKemKeyPair::generate().unwrap();
    let ed_seed = [0x11u8; 32];
    let pq_seed = [0x22u8; 32];
    let recipient_signing = SigningKeys::from_seeds(&ed_seed, &pq_seed);
    let recipient_vk = recipient_signing.verifying_keys();

    // Sender creates enrollment package
    let (pkg, _op_id) = sender_vault
        .create_enrollment_package(&recipient_vk, &recipient_dtk.public_key, None)
        .unwrap();

    // Serialize and deserialize package to CBOR
    let pkg_bytes = pkg.to_cbor().unwrap();
    let decoded_pkg = tn_proto::EnrollmentPackage::from_cbor(&pkg_bytes).unwrap();
    assert_eq!(pkg, decoded_pkg);

    // Recipient opens enrollment package
    let mut recipient_vault = Vault::from_enrollment_package(
        &recipient_db,
        Some("recpass"),
        &decoded_pkg,
        &recipient_dtk.private_key,
        &recipient_dtk.public_key,
        &sender_vk,
        ed_seed,
        pq_seed,
    )
    .unwrap();

    assert_eq!(recipient_vault.account_id(), sender_vault.account_id());

    // Recipient can create notes under the enrolled account
    let note_id = recipient_vault
        .new_note("Enrolled Note", "Body from enrolled device", vec![], None)
        .unwrap();
    let note = recipient_vault.get_note(note_id).unwrap();
    assert_eq!(note.body_md, "Body from enrolled device");

    // Tampered ciphertext fails fail-closed
    let mut tampered_pkg = decoded_pkg.clone();
    tampered_pkg.encrypted_payload[10] ^= 0xFF;
    let tamper_res = tampered_pkg.open(
        &recipient_dtk.private_key,
        &recipient_dtk.public_key,
        &sender_vk,
    );
    assert!(
        tamper_res.is_err(),
        "Tampered AEAD ciphertext must be rejected"
    );

    // Wrong private key fails fail-closed
    let rogue_dtk = HybridKemKeyPair::generate().unwrap();
    let wrong_key_res = decoded_pkg.open(
        &rogue_dtk.private_key,
        &recipient_dtk.public_key,
        &sender_vk,
    );
    assert!(
        wrong_key_res.is_err(),
        "Wrong private key must fail decapsulation"
    );
}

/// 3. Local IPC Daemon Lifecycle and Security Boundary Test (Threat S16).
#[test]
fn test_m5_local_ipc_daemon_lifecycle_and_security_boundary() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("daemon_vault.db");

    let (vault, _phrase) = Vault::create_new(&db_path, None).unwrap();
    let token = generate_auth_token().unwrap();

    let (server, listener) = DaemonServer::bind(Some(vault), db_path, token, 0).unwrap();
    let port = server.port();

    let shutdown = server.shutdown_signal();
    let handle = std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        while !shutdown.load(Ordering::SeqCst) {
            if let Ok((stream, _)) = listener.accept() {
                let _ = server.handle_client(stream);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let client = DaemonClient::new(port, token);

    // 1. Wait for daemon to accept connections and Ping
    let mut connected = false;
    for _ in 0..20 {
        if client.ping().is_ok() {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(connected, "Failed to connect to IPC daemon");

    // 2. Status
    let status = client.status().unwrap();
    assert!(!status.is_locked);
    assert_eq!(status.active_notes_count, 0);

    // 3. New Note
    let note_id = client
        .new_note(
            "Daemon Title".into(),
            "Daemon Body".into(),
            vec!["ipc".into()],
            None,
        )
        .unwrap();

    // 4. List Notes
    let notes = client.list_notes(false).unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].title, "Daemon Title");

    // 5. Get Note
    let detail = client.get_note(note_id).unwrap();
    assert_eq!(detail.body_md, "Daemon Body");

    // 6. Verify Local
    let rep = client.verify_local().unwrap();
    assert!(rep.valid);

    // 7. Rotate Key via IPC
    let (rot_op_id, new_phrase) = client.rotate_key().unwrap();
    assert!(!rot_op_id.as_bytes().is_empty());
    assert_eq!(new_phrase.split_whitespace().count(), 24);

    // 8. Lock & Unlock
    client.lock().unwrap();
    let status_locked = client.status().unwrap();
    assert!(status_locked.is_locked);
    assert!(client.list_notes(false).is_err());

    client.unlock(None).unwrap();
    let status_unlocked = client.status().unwrap();
    assert!(!status_unlocked.is_locked);

    // 9. Unauthorized rogue connection rejected (Threat S16)
    let bad_token = [0xEEu8; 32];
    let rogue_client = DaemonClient::new(port, bad_token);
    assert!(rogue_client.ping().is_err());
    assert!(rogue_client.list_notes(false).is_err());

    // 10. Stop
    client.stop().unwrap();
    handle.join().unwrap();
}

/// 4. Adversary drill: Forged key rotation rejected fail-closed (S18).
#[test]
fn test_m5_adversary_forged_key_rotation_fail_closed() {
    let mut server = Server::in_memory("test.origin".into()).unwrap();

    let legit_user_keys = SigningKeys::generate().unwrap();
    let legit_vk = legit_user_keys.verifying_keys();
    let account_id = tn_crypto::derive_account_id(&legit_vk.ed25519_bytes, &legit_vk.mldsa65_bytes);

    let reg_req = AccountRegisterReq {
        account_id,
        aik_ed_pub: legit_vk.ed25519_bytes,
        aik_pq_pub: legit_vk.mldsa65_bytes.clone(),
        initial_op: None,
        invite_token: None,
    };
    server
        .register_account(&reg_req, 1_700_000_000_000)
        .unwrap();

    // Attacker attempts key rotation signed by rogue keys
    let attacker_keys = SigningKeys::generate().unwrap();
    let rogue_new_keys = SigningKeys::generate().unwrap();

    let forged_payload = KeyRotatePayload::create(
        account_id,
        &rogue_new_keys,
        &attacker_keys, // Forged retiring AIK signature
        1_700_000_000_000,
    )
    .unwrap();
    let payload_cbor = forged_payload.to_cbor().unwrap();

    let header = OpHeader {
        v: 1,
        account_id,
        device_id: account_id,
        lane_seq: 0,
        lane_prev: None,
        hlc: Hlc::new(1_700_000_000_000, 0),
        kind: OpKind::KeyRotate,
        object_id: Id16::from_bytes([0u8; 16]),
        nk_wrap: None,
        nonce: [0u8; 24],
        deps: vec![],
        ct_hash: compute_ct_hash(&payload_cbor),
    };
    let op_id = compute_op_id(&header).unwrap();

    let mut sig_msg = Vec::new();
    sig_msg.extend_from_slice(tn_crypto::labels::LABEL_SIG_OP.as_bytes());
    sig_msg.extend_from_slice(op_id.as_bytes());
    let sig = legit_user_keys.sign(&sig_msg);

    let forged_op = Op {
        v: 1,
        account_id,
        device_id: account_id,
        lane_seq: 0,
        lane_prev: None,
        hlc: Hlc::new(1_700_000_000_000, 0),
        kind: OpKind::KeyRotate,
        object_id: Id16::from_bytes([0u8; 16]),
        nk_wrap: None,
        nonce: [0u8; 24],
        deps: vec![],
        ct: payload_cbor,
        sig_ed: sig.ed25519,
        sig_pq: sig.ml_dsa,
    };

    let submit_req = OpSubmitReq {
        ops: vec![forged_op],
        receipt_requested: true,
    };

    let req_bytes = tn_types::cbor::encode_canonical(&submit_req).unwrap();
    let nonce = [99u8; 16];
    let headers = tn_proto::sign_request(
        "POST",
        "/v1/ops",
        "",
        &req_bytes,
        account_id,
        &legit_user_keys,
        nonce,
        1_700_000_000_000,
        "test.origin",
    )
    .unwrap();

    let res = server.submit_ops(&submit_req, &headers, &legit_vk, 1_700_000_000_000);
    assert!(matches!(res, Err(TnError::BadSignature)));
}
