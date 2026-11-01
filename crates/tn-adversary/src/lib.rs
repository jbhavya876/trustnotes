#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-adversary`: Malicious server simulator and adversarial test harness (SPEC §7).
//!
//! Implements adversary simulation drivers for security claims C1-C10 and
//! adversary scenarios S1 through S17.
//!
//! Module M2 coverage:
//! - S4: Invalid server signature rejection.
//! - S6/S9: Tree rollback and backward timestamp rejection.
//! - S8: Insufficient witness threshold rejection.
//! - S13: Fail-closed on missing checkpoint (NEVER fallback to null/cached root).
//! - S14: Consistency proof root mismatch rejection.

use tn_core::sync::SyncTransport;
use tn_crypto::VerifyingKeys;
use tn_proto::{
    AccountHeadResp, AuthHeaders, ConsistencyProofResp, OpFetchResp, OpSubmitReq, OpSubmitResp,
};
use tn_server::Server;
use tn_tlog::Checkpoint;
use tn_types::{Id32, TnError};

/// Mock adversarial transport wrapper that allows intercepting and mutating responses.
pub struct AdversarialTransport<'a> {
    pub server: &'a mut Server,
    pub device_vk: VerifyingKeys,
    pub now_ms: u64,
    /// If true, simulate checkpoint endpoint failure (S13).
    pub drop_checkpoint: bool,
    /// If Some, override checkpoint response with malicious checkpoint.
    pub forged_checkpoint: Option<Checkpoint>,
    /// If Some, override account head response with malicious head (e.g. S6 rollback).
    pub forged_head: Option<AccountHeadResp>,
    /// If Some, override consistency proof with invalid proof (S14).
    pub forged_consistency_proof: Option<ConsistencyProofResp>,
}

impl<'a> AdversarialTransport<'a> {
    pub fn new(server: &'a mut Server, device_vk: VerifyingKeys, now_ms: u64) -> Self {
        Self {
            server,
            device_vk,
            now_ms,
            drop_checkpoint: false,
            forged_checkpoint: None,
            forged_head: None,
            forged_consistency_proof: None,
        }
    }
}

impl<'a> SyncTransport for AdversarialTransport<'a> {
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
        if let Some(head) = &self.forged_head {
            return Ok(head.clone());
        }
        self.server.get_account_head(account_id)
    }

    fn get_account_consistency_proof(
        &self,
        account_id: &Id32,
        from_size: u64,
    ) -> Result<ConsistencyProofResp, TnError> {
        if let Some(proof) = &self.forged_consistency_proof {
            return Ok(proof.clone());
        }
        self.server
            .get_account_consistency_proof(account_id, from_size)
    }

    fn get_checkpoint(&self) -> Result<Checkpoint, TnError> {
        if self.drop_checkpoint {
            return Err(TnError::Unavailable);
        }
        if let Some(cp) = &self.forged_checkpoint {
            return Ok(cp.clone());
        }
        self.server
            .get_checkpoint()
            .cloned()
            .ok_or(TnError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tn_core::{sync::SyncClient, vault::Vault};
    use tn_crypto::SigningKeys;
    use tn_proto::AccountRegisterReq;
    use tn_tlog::{Cosignature, WitnessPolicy};

    fn setup_test_env() -> (Server, WitnessPolicy, [u8; 32], [u8; 32]) {
        let server = Server::in_memory("test.adversary.origin".to_string()).unwrap();
        let w1 = [0x11u8; 32];
        let w2 = [0x22u8; 32];
        let policy = WitnessPolicy {
            threshold: 2,
            pinned_witnesses: vec![w1, w2],
            max_age_seconds: 300,
        };
        (server, policy, w1, w2)
    }

    /// Scenario S13: Checkpoint endpoint unreachable / missing.
    ///
    /// Client MUST abort sync with `TnError::Unavailable` and NEVER fall back
    /// to an unverified or cached root.
    #[test]
    fn adversary_scenario_s13_checkpoint_unavailable() {
        let (mut server, policy, _, _) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            1_700_000_000_000,
        );
        transport.drop_checkpoint = true;

        let res = client.pull_and_verify(&mut vault, &transport, 1_700_000_000_000);
        assert!(matches!(res, Err(TnError::Unavailable)));
    }

    /// Scenario S8: Witness threshold unsatisfied.
    ///
    /// Server provides a checkpoint with fewer than `k` valid cosignatures.
    /// Client MUST reject with `TnError::WitnessPolicy`.
    #[test]
    fn adversary_scenario_s8_insufficient_cosignatures() {
        let (mut server, policy, w1, _) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        let now_ms = 1_700_000_000_000u64;
        let mut cp = server.publish_epoch(now_ms).unwrap();
        // Policy requires 2 cosignatures, provide only 1
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp);

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::WitnessPolicy)));
    }

    /// Scenario S6/S9: Server attempts tree rollback.
    ///
    /// Server serves an account head smaller than local verified ops.
    /// Client MUST reject with `TnError::Rollback`.
    #[test]
    fn adversary_scenario_s6_rollback_rejected() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        // Local vault creates 2 notes
        let _ = vault.new_note("N1", "B1", vec![], None).unwrap();
        let _ = vault.new_note("N2", "B2", vec![], None).unwrap();

        let now_ms = 1_700_000_000_000u64;
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

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        // Adversary forges head with size 1 when local has 2 ops
        transport.forged_head = Some(AccountHeadResp {
            account_id: vault.account_id(),
            tree_size: 1,
            root_hash: [0xEE; 32],
        });

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::Rollback)));
    }

    /// Scenario S14: Consistency proof root mismatch.
    ///
    /// Server provides consistency proof with corrupted sibling path / forged root.
    /// Client MUST reject with `TnError::RootMismatch`.
    #[test]
    fn adversary_scenario_s14_consistency_root_mismatch() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        // Local vault creates 1 note
        let _ = vault.new_note("N1", "B1", vec![], None).unwrap();

        let now_ms = 1_700_000_000_000u64;
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

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        // Server claims size is 5 but provides bogus consistency path
        transport.forged_head = Some(AccountHeadResp {
            account_id: vault.account_id(),
            tree_size: 5,
            root_hash: [0x55; 32],
        });
        transport.forged_consistency_proof = Some(ConsistencyProofResp {
            old_size: 1,
            new_size: 5,
            path: vec![[0xAA; 32], [0xBB; 32]],
        });

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::RootMismatch)));
    }

    /// Scenario S7: Fork / Split View detection via device gossip (Claim C4, TRACEABILITY S7).
    ///
    /// Malicious server serves different account tree roots for the same tree size
    /// to Device 1 and Device 2.
    /// Device 1 and Device 2 exchange signed gossip messages.
    /// Verification MUST fail closed with `TnError::SplitView`.
    #[test]
    fn adversary_scenario_s7_fork_split_view() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();

        // 1. Device 1 creates vault and note
        let db1_path = dir.path().join("dev1.db");
        let (mut dev1, _) = Vault::create_new(&db1_path, Some("dev1-pass")).unwrap();
        let _ = dev1.new_note("D1 Note", "Body 1", vec![], None).unwrap();

        let dev1_vk = dev1.signing_keys_ref().verifying_keys();
        let now_ms = 1_700_000_000_000u64;

        // Device 2 keys
        let dev2_ed_seed = [0x77u8; 32];
        let dev2_pq_seed = [0x88u8; 32];
        let dev2_keys = SigningKeys::from_seeds(&dev2_ed_seed, &dev2_pq_seed);
        let dev2_vk = dev2_keys.verifying_keys();

        let (cert, _) = dev1.enroll_device(&dev2_vk, vec![0x11; 32], None).unwrap();

        // Register on server
        let reg_req = AccountRegisterReq {
            account_id: dev1.account_id(),
            aik_ed_pub: dev1_vk.ed25519_bytes,
            aik_pq_pub: dev1_vk.mldsa65_bytes.clone(),
            initial_op: None,
            invite_token: None,
        };
        server.register_account(&reg_req, now_ms).unwrap();

        // Server publishes checkpoint
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

        let mut client1 = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );
        {
            let mut t1 = AdversarialTransport::new(&mut server, dev1_vk.clone(), now_ms + 100);
            let _ = client1.push_ops(&dev1, &mut t1, now_ms + 100).unwrap();
        }

        let mut cp2 = server.publish_epoch(now_ms + 150).unwrap();
        cp2.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms + 150,
            sig_ed: [0u8; 64],
        });
        cp2.cosignatures.push(Cosignature {
            witness_key_id: w2,
            timestamp_ms: now_ms + 150,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp2);

        let report1 = {
            let t1 = AdversarialTransport::new(&mut server, dev1_vk, now_ms + 200);
            client1
                .pull_and_verify(&mut dev1, &t1, now_ms + 200)
                .unwrap()
        };

        // 2. Device 2 initializes from enrollment
        let db2_path = dir.path().join("dev2.db");
        let dev2 = Vault::from_enrollment(
            &db2_path,
            Some("dev2-pass"),
            *dev1.account_root().expose_bytes(),
            dev2_ed_seed,
            dev2_pq_seed,
            &cert,
        )
        .unwrap();

        // Adversary simulated: Device 2 observed a forked tree root (different root at size 2)
        let forked_root = [0xFA; 32];
        dev2.storage()
            .set_metadata("last_verified_tree_size", &2u64.to_le_bytes())
            .unwrap();
        dev2.storage()
            .set_metadata("last_verified_account_root", &forked_root)
            .unwrap();

        // 3. Device 2 creates gossip message of its observed state
        let gossip_dev2 = dev2
            .create_gossip(report1.checkpoint_log_size, [0x01; 32])
            .unwrap();

        // 4. Device 1 receives Device 2's gossip and verifies
        let split_view_result = dev1.verify_gossip(&gossip_dev2, &dev2_vk);

        // S7 assertion: MUST detect split view and fail closed with TnError::SplitView
        assert!(matches!(split_view_result, Err(TnError::SplitView)));
    }

    /// Scenario S10: Missed merge deadline (Claim C5).
    ///
    /// Op was receipted by server with `mmd_epoch = 1`, but server published
    /// subsequent checkpoints past `mmd_epoch` without including the op in the account tree.
    /// Client MUST fail closed with `TnError::MergeDeadlineMissed` and export
    /// an `EvidenceBundle`.
    #[test]
    fn adversary_scenario_s10_missed_merge_deadline() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        let now_ms = 1_700_000_000_000u64;

        // Register account on server
        let dev_vk = vault.signing_keys_ref().verifying_keys();
        let reg_req = AccountRegisterReq {
            account_id: vault.account_id(),
            aik_ed_pub: dev_vk.ed25519_bytes,
            aik_pq_pub: dev_vk.mldsa65_bytes.clone(),
            initial_op: None,
            invite_token: None,
        };
        server.register_account(&reg_req, now_ms).unwrap();

        // Local vault creates a note
        let _ = vault.new_note("Test Note", "Body", vec![], None).unwrap();

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        // Client pushes op, receives receipt with mmd_epoch
        let deadline = {
            let mut transport = AdversarialTransport::new(&mut server, dev_vk.clone(), now_ms);
            let receipts = client.push_ops(&vault, &mut transport, now_ms).unwrap();
            assert_eq!(receipts.len(), 1);
            receipts[0].mmd_epoch
        };

        // Adversary publishes checkpoints past the merge deadline (e.g. size >= deadline)
        let mut cp = Checkpoint {
            origin: "test.adversary.origin".to_string(),
            size: deadline,
            root_hash: [0x55; 32],
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
        server.set_latest_checkpoint(cp);

        // Adversary simulates omission: account head tree size is forged to 0 (omitted from tree)
        let mut transport = AdversarialTransport::new(&mut server, dev_vk, now_ms + 200);
        transport.forged_head = Some(AccountHeadResp {
            account_id: vault.account_id(),
            tree_size: 0,
            root_hash: [0u8; 32],
        });

        // Client attempts to pull and verify at epoch >= mmd_epoch
        let pull_res = client.pull_and_verify(&mut vault, &transport, now_ms + 200);

        // S10 assertion: MUST fail with MergeDeadlineMissed!
        assert!(matches!(pull_res, Err(TnError::MergeDeadlineMissed { .. })));

        // Verification: Evidence bundle was automatically persisted to metadata
        let evidence_cbor = vault
            .get_last_evidence_bundle()
            .unwrap()
            .expect("Evidence bundle recorded");
        let bundle = tn_proto::EvidenceBundle::from_cbor(&evidence_cbor).unwrap();
        assert_eq!(
            bundle.bundle_kind,
            tn_proto::EvidenceKind::MergeDeadlineMissed as u8
        );
        assert_eq!(bundle.account_id, vault.account_id());
    }

    /// Scenario S12: Server equivocation (Claim C5, C10).
    ///
    /// Server signs and publishes two conflicting checkpoint roots for the exact same size.
    /// MonitorAuditor MUST detect equivocation and return `TnError::Equivocation`.
    #[test]
    fn adversary_scenario_s12_server_equivocation() {
        let (server, policy, w1, w2) = setup_test_env();
        let now_ms = 1_700_000_000_000u64;

        let mut auditor = tn_monitor::MonitorAuditor::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        // Checkpoint A at size 10
        let mut cp_a = Checkpoint {
            origin: "test.adversary.origin".to_string(),
            size: 10,
            root_hash: [0xAA; 32],
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
        cp_a.server_sig = server.signing_keys().sign(&cp_a.signed_body());

        // Checkpoint B at same size 10 with conflicting root [0xBB; 32]
        let mut cp_b = Checkpoint {
            origin: "test.adversary.origin".to_string(),
            size: 10,
            root_hash: [0xBB; 32],
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
        cp_b.server_sig = server.signing_keys().sign(&cp_b.signed_body());

        // Audit first checkpoint: passes
        auditor.audit_checkpoint(&cp_a, None, now_ms).unwrap();

        // Audit second conflicting checkpoint: MUST detect equivocation!
        let err = auditor.audit_checkpoint(&cp_b, None, now_ms).unwrap_err();
        assert!(matches!(err, TnError::Equivocation { epoch: 10 }));
    }

    /// Scenario S17: Unlogged server key change (Claim C10).
    ///
    /// Malicious server changes its signing key without a transparent key change log entry.
    /// Monitor and client MUST reject with `TnError::BadSignature`.
    #[test]
    fn adversary_scenario_s17_unlogged_key_change() {
        let (server, policy, w1, w2) = setup_test_env();
        let now_ms = 1_700_000_000_000u64;

        let mut auditor = tn_monitor::MonitorAuditor::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        // Rogue attacker generates new signing key not matching pinned server_vk
        let rogue_keys = SigningKeys::generate().unwrap();

        let mut cp_rogue = Checkpoint {
            origin: "test.adversary.origin".to_string(),
            size: 1,
            root_hash: [0x55; 32],
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
        cp_rogue.server_sig = rogue_keys.sign(&cp_rogue.signed_body());

        let res = auditor.audit_checkpoint(&cp_rogue, None, now_ms);
        assert!(matches!(res, Err(TnError::BadSignature)));
    }

    /// Scenario S16: Cross-user local IPC unauthorized access (Threat S16, Claim C8).
    ///
    /// Malicious unprivileged process tries to query the daemon without the 256-bit token.
    /// Daemon MUST reject without revealing note data or status.
    #[test]
    fn adversary_scenario_s16_unauthorized_ipc_access() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        use tn_core::{generate_auth_token, DaemonClient, DaemonServer, Vault};

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (vault, _) = Vault::create_new(&db_path, None).unwrap();
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

        // 1. Rogue client connects with all-zero or forged token
        let rogue_token = [0x55u8; 32];
        let rogue_client = DaemonClient::new(port, rogue_token);

        let ping_res = rogue_client.ping();
        assert!(ping_res.is_err(), "Rogue client ping must be rejected");

        let notes_res = rogue_client.list_notes(false);
        assert!(
            notes_res.is_err(),
            "Rogue client reading notes must be rejected"
        );

        // 2. Legitimate client connects with true token
        let legit_client = DaemonClient::new(port, token);
        assert!(legit_client.ping().is_ok());

        legit_client.stop().unwrap();
        handle.join().unwrap();
    }

    /// Scenario S18: Forged or unauthorized key rotation op rejected fail-closed (ADR-0002).
    ///
    /// Attacker attempts to submit a KeyRotate op signed by a rogue AIK without authorization
    /// from the active account key. Server sequencer MUST reject fail-closed with BadSignature.
    #[test]
    fn adversary_scenario_s18_forged_key_rotate_op() {
        use tn_oplog::{compute_ct_hash, compute_op_id, Hlc, Op, OpHeader};
        use tn_proto::{AccountRegisterReq, KeyRotatePayload, OpSubmitReq};
        use tn_types::{Id16, OpKind};

        let mut server = Server::in_memory("test.origin".into()).unwrap();

        let legit_user_keys = SigningKeys::generate().unwrap();
        let legit_vk = legit_user_keys.verifying_keys();
        let account_id =
            tn_crypto::derive_account_id(&legit_vk.ed25519_bytes, &legit_vk.mldsa65_bytes);

        // Register legitimate account and enroll initial device
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

        // Attacker generates rogue replacement keys
        let attacker_keys = SigningKeys::generate().unwrap();
        let rogue_new_keys = SigningKeys::generate().unwrap();

        // Attacker creates KeyRotate payload signed by attacker_keys (NOT legit_user_keys)
        let forged_payload = KeyRotatePayload::create(
            account_id,
            &rogue_new_keys,
            &attacker_keys, // Forged old AIK signature!
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
        let nonce = [1u8; 16];
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

        // Server sequencer submission must reject the forged KeyRotate op
        let res = server.submit_ops(&submit_req, &headers, &legit_vk, 1_700_000_000_000);
        assert!(matches!(res, Err(TnError::BadSignature)));
    }
}
