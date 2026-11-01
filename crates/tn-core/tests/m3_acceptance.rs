#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Acceptance test suite for Module M3 (Multi-Device Sync & Identity).
//!
//! Enforces:
//! - Device enrollment via AIK-signed `DeviceCertificate` (ADR-0002).
//! - Multi-device concurrent editing on independent monotonic lanes.
//! - Server sequencing across multiple device lanes without gaps or forks.
//! - S5 adversary defense: ops from revoked devices rejected by server and clients.
//! - Multi-device DAG convergence on concurrent note edits.

use tempfile::tempdir;
use tn_core::{
    sync::{SyncClient, SyncTransport},
    vault::Vault,
};
use tn_crypto::{derive_device_id, SigningKeys, VerifyingKeys};
use tn_proto::{
    AccountHeadResp, AccountRegisterReq, AuthHeaders, ConsistencyProofResp, OpFetchResp,
    OpSubmitReq, OpSubmitResp,
};
use tn_server::Server;
use tn_tlog::{Checkpoint, Cosignature, WitnessPolicy};
use tn_types::{Id32, TnError};

/// In-memory transport adapter for testing multiple devices against a single server.
struct MultiDeviceTestTransport<'a> {
    server: &'a mut Server,
    device_vk: VerifyingKeys,
    now_ms: u64,
}

impl<'a> SyncTransport for MultiDeviceTestTransport<'a> {
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

fn publish_and_cosign(server: &mut Server, now_ms: u64, w1: [u8; 32], w2: [u8; 32]) {
    let mut cp = server.publish_epoch(now_ms).unwrap();
    cp.cosignatures.push(Cosignature {
        witness_key_id: w1,
        timestamp_ms: now_ms,
        sig_ed: [0u8; 64],
    });
    cp.cosignatures.push(Cosignature {
        witness_key_id: w2,
        timestamp_ms: now_ms,
        sig_ed: [0u8; 64],
    });
    server.set_latest_checkpoint(cp);
}

#[test]
fn test_m3_multi_device_enrollment_and_sync() {
    let mut server = Server::in_memory("origin.trustnotes.test".to_string()).unwrap();
    let w1 = [0x11u8; 32];
    let w2 = [0x22u8; 32];
    let policy = WitnessPolicy {
        threshold: 2,
        pinned_witnesses: vec![w1, w2],
        max_age_seconds: 300,
    };

    let dir = tempdir().unwrap();
    let now_ms = 1_700_000_000_000u64;

    // 1. Device 1 (Desktop) creates vault
    let db1_path = dir.path().join("dev1.db");
    let (mut dev1, _) = Vault::create_new(&db1_path, Some("pass-dev1")).unwrap();
    let account_id = dev1.account_id();

    // Register account on server
    server
        .register_account(
            &AccountRegisterReq {
                account_id,
                aik_ed_pub: [1u8; 32],
                aik_pq_pub: vec![2u8; 100],
                initial_op: None,
                invite_token: None,
            },
            now_ms,
        )
        .unwrap();

    let mut client = SyncClient::new(
        "origin.trustnotes.test".to_string(),
        server.verifying_keys(),
        policy.clone(),
    );

    // Device 1 writes Note 1
    let note1_id = dev1
        .new_note(
            "Desktop Note",
            "Created on desktop",
            vec!["work".into()],
            None,
        )
        .unwrap();

    // Device 1 pushes ops
    let dev1_vk = dev1.signing_keys_ref().verifying_keys();
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 100,
        };
        let receipts = client.push_ops(&dev1, &mut t1, now_ms + 100).unwrap();
        assert_eq!(receipts.len(), 1);
    }

    // 2. Device 2 (Laptop) generates key material
    let dev2_ed_seed = [0x55u8; 32];
    let dev2_pq_seed = [0x66u8; 32];
    let dev2_keys = SigningKeys::from_seeds(&dev2_ed_seed, &dev2_pq_seed);
    let dev2_vk = dev2_keys.verifying_keys();

    // Device 1 enrolls Device 2 (issues AIK cross-signed cert & DeviceAdd op)
    let (cert, _) = dev1.enroll_device(&dev2_vk, vec![0x77; 32], None).unwrap();
    assert_eq!(
        cert.device_id,
        derive_device_id(&dev2_vk.ed25519_bytes, &dev2_vk.mldsa65_bytes)
    );

    // Device 1 pushes the enrollment op to server
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 200,
        };
        let receipts = client.push_ops(&dev1, &mut t1, now_ms + 200).unwrap();
        assert_eq!(receipts.len(), 1); // DeviceAdd
    }

    // Server publishes epoch and witnesses cosign
    publish_and_cosign(&mut server, now_ms + 300, w1, w2);

    // Device 1 syncs (verifies up to size 2)
    {
        let t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 350,
        };
        client
            .pull_and_verify(&mut dev1, &t1, now_ms + 350)
            .unwrap();
    }

    // 3. Device 2 initializes vault via `from_enrollment`
    let db2_path = dir.path().join("dev2.db");
    let mut dev2 = Vault::from_enrollment(
        &db2_path,
        Some("pass-dev2"),
        *dev1.account_root().expose_bytes(),
        dev2_ed_seed,
        dev2_pq_seed,
        &cert,
    )
    .unwrap();
    assert_eq!(dev2.account_id(), account_id);
    assert_eq!(dev2.device_id(), cert.device_id);

    // Device 2 syncs from server (pulls Note 1 and DeviceAdd op)
    {
        let t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 400,
        };
        let report = client
            .pull_and_verify(&mut dev2, &t2, now_ms + 400)
            .unwrap();
        assert_eq!(report.ops_pulled, 2);
    }

    // Device 2 can now read Note 1
    let note1_detail = dev2.get_note(note1_id).unwrap();
    assert_eq!(note1_detail.summary.title, "Desktop Note");

    // 4. Device 2 creates Note 2 on its own lane (lane_seq 0 for dev2)
    let note2_id = dev2
        .new_note(
            "Laptop Note",
            "Created on laptop",
            vec!["mobile".into()],
            None,
        )
        .unwrap();

    // Device 2 pushes Note 2 to server
    {
        let mut t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 500,
        };
        let receipts = client.push_ops(&dev2, &mut t2, now_ms + 500).unwrap();
        assert_eq!(receipts.len(), 1);
    }

    // Server publishes epoch
    publish_and_cosign(&mut server, now_ms + 600, w1, w2);

    // 5. Device 1 pulls ops from server (pulls Note 2 from dev2)
    {
        let t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 700,
        };
        let report = client
            .pull_and_verify(&mut dev1, &t1, now_ms + 700)
            .unwrap();
        assert_eq!(report.ops_pulled, 1);
    }

    // Device 1 now observes Note 2 created by Device 2
    let note2_detail = dev1.get_note(note2_id).unwrap();
    assert_eq!(note2_detail.summary.title, "Laptop Note");
    assert_eq!(dev1.list_notes(false).unwrap().len(), 2);
    assert_eq!(dev2.list_notes(false).unwrap().len(), 2);
}

#[test]
fn test_m3_device_revocation_enforcement_s5() {
    let mut server = Server::in_memory("origin.trustnotes.test".to_string()).unwrap();
    let w1 = [0x11u8; 32];
    let w2 = [0x22u8; 32];
    let policy = WitnessPolicy {
        threshold: 2,
        pinned_witnesses: vec![w1, w2],
        max_age_seconds: 300,
    };

    let dir = tempdir().unwrap();
    let now_ms = 1_700_000_000_000u64;

    // 1. Device 1 creates vault
    let db1_path = dir.path().join("dev1.db");
    let (mut dev1, _) = Vault::create_new(&db1_path, Some("pass-dev1")).unwrap();
    let account_id = dev1.account_id();

    server
        .register_account(
            &AccountRegisterReq {
                account_id,
                aik_ed_pub: [1u8; 32],
                aik_pq_pub: vec![2u8; 100],
                initial_op: None,
                invite_token: None,
            },
            now_ms,
        )
        .unwrap();

    let client = SyncClient::new(
        "origin.trustnotes.test".to_string(),
        server.verifying_keys(),
        policy,
    );

    // 2. Enroll Device 2
    let dev2_ed_seed = [0x33u8; 32];
    let dev2_pq_seed = [0x44u8; 32];
    let dev2_keys = SigningKeys::from_seeds(&dev2_ed_seed, &dev2_pq_seed);
    let dev2_vk = dev2_keys.verifying_keys();

    let (cert, _) = dev1.enroll_device(&dev2_vk, vec![0x11; 32], None).unwrap();

    let dev1_vk = dev1.signing_keys_ref().verifying_keys();
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 100,
        };
        client.push_ops(&dev1, &mut t1, now_ms + 100).unwrap();
    }

    let dev2_id = cert.device_id;

    // 3. Device 1 revokes Device 2 (Scenario S5)
    dev1.revoke_device(dev2_id, Some("Device stolen".to_string()))
        .unwrap();

    // Device 1 pushes revocation op to server
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 200,
        };
        let receipts = client.push_ops(&dev1, &mut t1, now_ms + 200).unwrap();
        assert_eq!(receipts.len(), 1); // DeviceRevoke
    }

    // 4. Device 2 attempts to author an op and submit to server
    let db2_path = dir.path().join("dev2.db");
    let mut dev2 = Vault::from_enrollment(
        &db2_path,
        Some("pass-dev2"),
        *dev1.account_root().expose_bytes(),
        dev2_ed_seed,
        dev2_pq_seed,
        &cert,
    )
    .unwrap();

    dev2.new_note("Malicious Note", "Attempt from stolen phone", vec![], None)
        .unwrap();

    // Submission to server MUST fail with TnError::RevokedDevice (Scenario S5)
    {
        let mut t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 300,
        };
        let res = client.push_ops(&dev2, &mut t2, now_ms + 300);
        assert!(matches!(res, Err(TnError::RevokedDevice)));
    }
}

#[test]
fn test_m3_concurrent_multi_device_dag_convergence() {
    let mut server = Server::in_memory("origin.trustnotes.test".to_string()).unwrap();
    let w1 = [0x11u8; 32];
    let w2 = [0x22u8; 32];
    let policy = WitnessPolicy {
        threshold: 2,
        pinned_witnesses: vec![w1, w2],
        max_age_seconds: 300,
    };

    let dir = tempdir().unwrap();
    let now_ms = 1_700_000_000_000u64;

    // 1. Device 1 creates note
    let db1_path = dir.path().join("dev1.db");
    let (mut dev1, _) = Vault::create_new(&db1_path, Some("pass-dev1")).unwrap();
    let account_id = dev1.account_id();

    server
        .register_account(
            &AccountRegisterReq {
                account_id,
                aik_ed_pub: [1u8; 32],
                aik_pq_pub: vec![2u8; 100],
                initial_op: None,
                invite_token: None,
            },
            now_ms,
        )
        .unwrap();

    let mut client = SyncClient::new(
        "origin.trustnotes.test".to_string(),
        server.verifying_keys(),
        policy,
    );

    let note_id = dev1
        .new_note("Initial Title", "Initial content", vec!["v1".into()], None)
        .unwrap();

    let dev1_vk = dev1.signing_keys_ref().verifying_keys();

    // 2. Enroll Device 2
    let dev2_ed_seed = [0x77u8; 32];
    let dev2_pq_seed = [0x88u8; 32];
    let dev2_keys = SigningKeys::from_seeds(&dev2_ed_seed, &dev2_pq_seed);
    let dev2_vk = dev2_keys.verifying_keys();

    let (cert, _) = dev1.enroll_device(&dev2_vk, vec![0x22; 32], None).unwrap();

    // Push initial note + enrollment
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 100,
        };
        client.push_ops(&dev1, &mut t1, now_ms + 100).unwrap();
    }

    publish_and_cosign(&mut server, now_ms + 200, w1, w2);

    // Device 2 initializes and syncs
    let db2_path = dir.path().join("dev2.db");
    let mut dev2 = Vault::from_enrollment(
        &db2_path,
        Some("pass-dev2"),
        *dev1.account_root().expose_bytes(),
        dev2_ed_seed,
        dev2_pq_seed,
        &cert,
    )
    .unwrap();

    {
        let t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 300,
        };
        client
            .pull_and_verify(&mut dev2, &t2, now_ms + 300)
            .unwrap();
    }

    // 3. CONCURRENT EDITS: Both devices edit note without pulling each other's edits
    // Device 1 edits
    let _ = dev1
        .edit_note(
            note_id,
            "Device 1 Title",
            "Edited by device 1",
            vec!["dev1".into()],
        )
        .unwrap();

    // Device 2 edits concurrently
    let _ = dev2
        .edit_note(
            note_id,
            "Device 2 Title",
            "Edited by device 2",
            vec!["dev2".into()],
        )
        .unwrap();

    // Both push to server
    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 400,
        };
        client.push_ops(&dev1, &mut t1, now_ms + 400).unwrap();
    }

    {
        let mut t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 410,
        };
        client.push_ops(&dev2, &mut t2, now_ms + 410).unwrap();
    }

    publish_and_cosign(&mut server, now_ms + 500, w1, w2);

    // 4. Both pull updates: both observe the concurrent sibling ops
    {
        let t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 600,
        };
        client
            .pull_and_verify(&mut dev1, &t1, now_ms + 600)
            .unwrap();
    }

    {
        let t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 610,
        };
        client
            .pull_and_verify(&mut dev2, &t2, now_ms + 610)
            .unwrap();
    }

    // Both notes should be readable on both devices
    let note_dev1 = dev1.get_note(note_id).unwrap();
    let note_dev2 = dev2.get_note(note_id).unwrap();
    assert_eq!(note_dev1.summary.object_id, note_id);
    assert_eq!(note_dev2.summary.object_id, note_id);

    // 5. Device 1 creates converged merge edit
    let _ = dev1
        .edit_note(
            note_id,
            "Converged Title",
            "Merged content from both devices",
            vec!["converged".into()],
        )
        .unwrap();

    {
        let mut t1 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev1_vk.clone(),
            now_ms: now_ms + 700,
        };
        client.push_ops(&dev1, &mut t1, now_ms + 700).unwrap();
    }

    publish_and_cosign(&mut server, now_ms + 800, w1, w2);

    // Device 2 pulls converged state
    {
        let t2 = MultiDeviceTestTransport {
            server: &mut server,
            device_vk: dev2_vk.clone(),
            now_ms: now_ms + 900,
        };
        client
            .pull_and_verify(&mut dev2, &t2, now_ms + 900)
            .unwrap();
    }

    let final_1 = dev1.get_note(note_id).unwrap();
    let final_2 = dev2.get_note(note_id).unwrap();
    assert_eq!(final_1.summary.title, "Converged Title");
    assert_eq!(final_2.summary.title, "Converged Title");
    assert_eq!(final_1.body_md, "Merged content from both devices");
    assert_eq!(final_2.body_md, "Merged content from both devices");
}
