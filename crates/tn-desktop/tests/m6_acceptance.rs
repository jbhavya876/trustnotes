#![forbid(unsafe_code)]

//! Milestone M6 Acceptance Test Suite: Desktop Client, Verification Panel,
//! Chunked Encrypted Attachments & AI Security Boundary.
//!
//! Validates:
//! 1. 1 MiB Encrypted Chunked Attachments (roundtrip, tampering, reordering, wrong key).
//! 2. AI Security Boundary (Claim C1, C10): Disabled by default, localhost-only validation,
//!    affirmative per-call consent gating, and encrypted egress receipts.
//! 3. Outbound Network Egress Allow-List (Claim C1): Intercepts and blocks any unauthorized remote egress.
//! 4. Embedded Desktop UI Server & Strict CSP: Zero remote content, strict headers,
//!    verification panel statistics, and evidence bundle export.

use std::io::{Read, Write};
use std::net::TcpStream;
use tn_core::ai::{AiBoundaryGuard, AiConsentToken, DisabledAiProvider, LocalhostAiProvider};
use tn_core::attachment::{open_attachment, seal_attachment, DEFAULT_CHUNK_SIZE};
use tn_desktop::egress::EgressAllowList;
use tn_desktop::server::{DesktopServer, STRICT_CSP_HEADER};
use tn_types::{Id16, TnError};

#[test]
fn test_m6_chunked_encrypted_attachments_roundtrip_and_tamper() {
    let note_key = [0x77u8; 32];

    // Create 3.5 MiB test data (3 * 1 MiB + 512 KiB)
    let total_bytes = 3 * DEFAULT_CHUNK_SIZE + 512 * 1024;
    let mut large_file = Vec::with_capacity(total_bytes);
    for i in 0..total_bytes {
        large_file.push(((i % 251) ^ 0x5C) as u8);
    }

    // Seal attachment into 1 MiB chunks
    let (manifest, chunks) = seal_attachment(
        "large_confidential_dataset.dat",
        "application/octet-stream",
        &large_file,
        &note_key,
    )
    .expect("sealing failed");

    assert_eq!(manifest.filename, "large_confidential_dataset.dat");
    assert_eq!(manifest.mime_type, "application/octet-stream");
    assert_eq!(manifest.total_size, total_bytes as u64);
    assert_eq!(manifest.chunk_size, DEFAULT_CHUNK_SIZE as u32);
    assert_eq!(manifest.chunk_hashes.len(), 4);
    assert_eq!(chunks.len(), 4);

    // 1. Bit-for-bit roundtrip
    let reassembled =
        open_attachment(&manifest, &chunks, &note_key).expect("open unmodified chunks failed");
    assert_eq!(reassembled, large_file);

    // 2. Tampering a byte in chunk 2 must fail closed
    let mut tampered_chunks = chunks.clone();
    if let Some(byte) = tampered_chunks[2].ciphertext.last_mut() {
        *byte ^= 0x01;
    }
    let err_tamper = open_attachment(&manifest, &tampered_chunks, &note_key);
    assert!(
        matches!(err_tamper, Err(TnError::AttachmentTampered)),
        "Tampered chunk must fail with AttachmentTampered"
    );

    // 3. Reordering chunks (e.g. swap chunk 0 and chunk 1) must fail closed
    let mut reordered_chunks = chunks.clone();
    reordered_chunks.swap(0, 1);
    let err_reorder = open_attachment(&manifest, &reordered_chunks, &note_key);
    assert!(
        matches!(err_reorder, Err(TnError::AttachmentTampered)),
        "Reordered chunks must fail with AttachmentTampered"
    );

    // 4. Opening with wrong NoteKey must fail closed
    let wrong_key = [0x99u8; 32];
    let err_wrong_key = open_attachment(&manifest, &chunks, &wrong_key);
    assert!(
        matches!(err_wrong_key, Err(TnError::AttachmentTampered)),
        "Wrong key must fail with AttachmentTampered"
    );
}

#[test]
fn test_m6_ai_boundary_fail_closed_and_egress_receipts() {
    let note_id = Id16::from_bytes([0x12; 16]);

    // 1. Default DisabledAiProvider immediately fails closed
    let disabled = DisabledAiProvider;
    let consent = AiConsentToken::new(note_id, 1000, 60_000).expect("token");
    let mut guard_disabled = AiBoundaryGuard::new(disabled);

    let res_disabled = guard_disabled.execute_completion(
        "Summarize private cryptographic notes",
        note_id,
        &consent,
        1005,
    );
    assert!(
        matches!(res_disabled, Err(TnError::AiDisabled)),
        "Disabled AI must return TnError::AiDisabled"
    );
    assert_eq!(guard_disabled.receipts().len(), 1);
    assert!(!guard_disabled.receipts()[0].success);

    // 2. Remote endpoint disallowed at construction
    let remote_urls = [
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "http://external-inference-cloud.org:8080",
    ];
    for url in remote_urls {
        let err = LocalhostAiProvider::new(url);
        assert!(
            matches!(err, Err(TnError::AiRemoteDisallowed(_))),
            "Remote endpoint {url} must fail construction"
        );
    }

    // 3. Localhost provider succeeds only with affirmative, unexpired consent
    let localhost = LocalhostAiProvider::new_with_mock(
        "http://127.0.0.1:11434/api/generate",
        Some("Summary: The Merkle tree and hybrid signatures guarantee integrity.".into()),
    )
    .expect("localhost provider");

    let mut guard_local = AiBoundaryGuard::new(localhost);

    // 3a. Calling without matching note ID in consent fails
    let wrong_note_id = Id16::from_bytes([0x99; 16]);
    let err_wrong_consent = guard_local.execute_completion(
        "Prompt text",
        wrong_note_id,
        &consent, // covers note_id, not wrong_note_id
        1005,
    );
    assert!(matches!(err_wrong_consent, Err(TnError::AiConsentDenied)));

    // 3b. Calling with expired consent fails
    let expired_consent = AiConsentToken::new(note_id, 1000, 100).expect("token");
    let err_expired = guard_local.execute_completion(
        "Prompt text",
        note_id,
        &expired_consent,
        1500, // expired at 1100
    );
    assert!(matches!(err_expired, Err(TnError::AiConsentDenied)));

    // 3c. Valid consent executes and writes an encrypted egress receipt
    let valid_consent = AiConsentToken::new(note_id, 2000, 60_000).expect("token");
    let completion = guard_local
        .execute_completion("Summarize the architecture", note_id, &valid_consent, 2010)
        .expect("completion succeeded");

    assert!(completion.contains("Merkle tree"));
    let receipts = guard_local.receipts();
    assert_eq!(receipts.len(), 3); // 2 failed + 1 successful
    let last_receipt = &receipts[2];
    assert!(last_receipt.success);
    assert_eq!(last_receipt.provider_name, "localhost");
    assert_eq!(
        last_receipt.endpoint_url,
        "http://127.0.0.1:11434/api/generate"
    );
    assert_eq!(last_receipt.consent_token_id, valid_consent.token_id);
    assert_ne!(last_receipt.prompt_sha256, [0u8; 32]);
}

#[test]
fn test_m6_egress_allow_list_policy() {
    let allow_list = EgressAllowList::new(
        "sync.trustnotes.internal",
        &["witness1.internal", "witness2.internal"],
        &["alice.btc.calendar.opentimestamps.org"],
        Some(11434),
    );

    // Permitted endpoints
    assert!(allow_list
        .check_egress("https://sync.trustnotes.internal/v1/op")
        .is_ok());
    assert!(allow_list
        .check_egress("https://witness1.internal/v1/checkpoint")
        .is_ok());
    assert!(allow_list
        .check_egress("https://alice.btc.calendar.opentimestamps.org/digest")
        .is_ok());
    assert!(allow_list
        .check_egress("http://127.0.0.1:11434/api/generate")
        .is_ok());

    // Prohibited external endpoints
    assert!(matches!(
        allow_list.check_egress("https://telemetry.trustnotes.internal"),
        Err(TnError::EgressViolation(_))
    ));
    assert!(matches!(
        allow_list.check_egress("https://cdn.jsdelivr.net/npm/bootstrap"),
        Err(TnError::EgressViolation(_))
    ));
    assert!(matches!(
        allow_list.check_egress("https://api.openai.com/v1/models"),
        Err(TnError::EgressViolation(_))
    ));
    // Disallowed port on localhost
    assert!(matches!(
        allow_list.check_egress("http://127.0.0.1:9090/metrics"),
        Err(TnError::EgressViolation(_))
    ));
}

#[test]
fn test_m6_desktop_embedded_server_csp_and_zero_remote_resources() {
    let ai_provider = LocalhostAiProvider::new_with_mock(
        "http://127.0.0.1:11434/api/generate",
        Some("Local response".into()),
    )
    .expect("ai provider");

    let server = DesktopServer::start(0, None, ai_provider).expect("start server");
    let port = server.port();

    // 1. Fetch index.html and verify headers
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("write GET");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains(&format!("Content-Security-Policy: {STRICT_CSP_HEADER}")));
    assert!(response.contains("X-Content-Type-Options: nosniff"));
    assert!(response.contains("X-Frame-Options: DENY"));
    assert!(response.contains("Cache-Control: no-store"));
    assert!(response.contains("TrustNotes"));

    // 2. Query Verification Status API
    let mut stream_verify = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream_verify
        .write_all(b"GET /api/verification HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("write");
    let mut resp_verify = String::new();
    stream_verify
        .read_to_string(&mut resp_verify)
        .expect("read");

    assert!(resp_verify.contains("verified_final_count"));
    assert!(resp_verify.contains("provisional_count"));
    assert!(resp_verify.contains("last_checkpoint_root"));
    assert!(resp_verify.contains("ots_status"));

    // 3. Query Evidence Export API
    let mut stream_evidence = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream_evidence
        .write_all(
            b"POST /api/evidence/export HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("write");
    let mut resp_evidence = String::new();
    stream_evidence
        .read_to_string(&mut resp_evidence)
        .expect("read");

    assert!(resp_evidence.contains("checkpoint_root"));
    assert!(resp_evidence.contains("ots_proof"));

    server.stop();
}
