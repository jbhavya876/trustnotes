#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Client Synchronization Engine & Verification Pipeline (SPEC §5).
//!
//! Enforces:
//! - Fail-closed execution: any cryptographic or structural defect immediately aborts sync.
//! - S13 Guard: Checkpoint fetch failure emits `TnError::Unavailable`. Never falls back to default/cached root.
//! - S14 Guard: Consistency proof root verified against expected root. Mismatch emits `TnError::RootMismatch`.
//! - S6/S9 Guard: Rollback of tree size or timestamp emits `TnError::Rollback`.
//! - S8 Guard: Fewer than k valid witness cosignatures emits `TnError::WitnessPolicy`.
//! - C1 & C3: All op ciphertexts verified before ingestion.

use tn_crypto::VerifyingKeys;
use tn_merkle::{verify_consistency, ConsistencyProof, MerkleRoot};
use tn_proto::{
    sign_request, AccountHeadResp, AuthHeaders, ConsistencyProofResp, OpFetchResp, OpSubmitReq,
    OpSubmitResp, Receipt,
};
use tn_tlog::{verify_checkpoint, Checkpoint, WitnessPolicy};
use tn_types::{Id32, TnError};

use crate::vault::Vault;

/// Trait abstracting client-server network transport for sync operations.
pub trait SyncTransport {
    /// Submits a batch of operations with `X-TN-*` authentication headers.
    fn submit_ops(
        &mut self,
        req: &OpSubmitReq,
        headers: &AuthHeaders,
    ) -> Result<OpSubmitResp, TnError>;

    /// Fetches operations for an account after `after_index` (or from beginning if `None`).
    fn fetch_ops(
        &self,
        account_id: &Id32,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<OpFetchResp, TnError>;

    /// Fetches current account head metadata.
    fn get_account_head(&self, account_id: &Id32) -> Result<AccountHeadResp, TnError>;

    /// Fetches consistency proof between two account tree sizes.
    fn get_account_consistency_proof(
        &self,
        account_id: &Id32,
        from_size: u64,
    ) -> Result<ConsistencyProofResp, TnError>;

    /// Fetches latest witnessed checkpoint (fails closed with `TnError::Unavailable` if missing).
    fn get_checkpoint(&self) -> Result<Checkpoint, TnError>;
}

/// Summary report emitted after a successful sync cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Number of local ops pushed to server.
    pub ops_pushed: usize,
    /// Number of receipts collected from server.
    pub receipts_collected: usize,
    /// Number of remote ops pulled from server.
    pub ops_pulled: usize,
    /// Total verified ops now in local vault.
    pub total_verified_ops: usize,
    /// Global transparency log checkpoint size verified.
    pub checkpoint_log_size: u64,
}

/// Client synchronization manager executing the fail-closed verification pipeline.
pub struct SyncClient {
    server_origin: String,
    server_vk: VerifyingKeys,
    policy: WitnessPolicy,
    last_checkpoint_size: u64,
    last_checkpoint_ts: u64,
}

impl SyncClient {
    /// Creates a new SyncClient with pinned server public keys and witness policy.
    #[must_use]
    pub fn new(server_origin: String, server_vk: VerifyingKeys, policy: WitnessPolicy) -> Self {
        Self {
            server_origin,
            server_vk,
            policy,
            last_checkpoint_size: 0,
            last_checkpoint_ts: 0,
        }
    }

    /// Pushes unpushed local operations to the server transport.
    ///
    /// # Errors
    /// Returns `TnError` if server rejects batch or authentication fails.
    pub fn push_ops<T: SyncTransport>(
        &self,
        vault: &Vault,
        transport: &mut T,
        now_ms: u64,
    ) -> Result<Vec<Receipt>, TnError> {
        let last_pushed_seq = vault
            .storage()
            .get_metadata("last_pushed_lane_seq")?
            .and_then(|bytes| {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    Some(u64::from_le_bytes(arr))
                } else {
                    None
                }
            });

        let all_ops = vault.get_all_ops_internal()?;
        let mut ops_to_push = Vec::new();
        let mut max_seq = last_pushed_seq;

        for (_, op) in all_ops {
            // Only push ops authored by this device
            if op.device_id == vault.device_id() {
                let should_push = match last_pushed_seq {
                    Some(last) => op.lane_seq > last,
                    None => true,
                };
                if should_push {
                    if max_seq.is_none_or(|m| op.lane_seq > m) {
                        max_seq = Some(op.lane_seq);
                    }
                    ops_to_push.push(op);
                }
            }
        }

        if ops_to_push.is_empty() {
            return Ok(vec![]);
        }

        let submit_req = OpSubmitReq {
            ops: ops_to_push,
            receipt_requested: true,
        };

        let req_bytes = tn_types::cbor::encode_canonical(&submit_req)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| TnError::Internal(format!("Nonce gen error: {e}")))?;

        let headers = sign_request(
            "POST",
            "/v1/ops",
            "",
            &req_bytes,
            vault.device_id(),
            vault.signing_keys_ref(),
            nonce,
            now_ms,
            &self.server_origin,
        )?;

        let resp = transport.submit_ops(&submit_req, &headers)?;

        // Verify all receipts returned by server
        for r in &resp.receipts {
            r.verify(&self.server_vk)?;
        }

        if let Some(m) = max_seq {
            vault
                .storage()
                .set_metadata("last_pushed_lane_seq", &m.to_le_bytes())?;
        }

        Ok(resp.receipts)
    }

    /// Executes the full client sync verification pipeline (SPEC §5).
    ///
    /// 1. Fetch & Verify Checkpoint (S13 guard: aborts with `Unavailable` on missing/bad checkpoint).
    /// 2. Fetch & Verify Consistency Proof for Account Tree (S14 guard: asserts root matches).
    /// 3. Fetch & Verify Ops (checks signatures, lane continuity, AEAD decryption).
    ///
    /// # Errors
    /// Fails closed: returns typed `TnError` on any verification failure.
    pub fn pull_and_verify<T: SyncTransport>(
        &mut self,
        vault: &mut Vault,
        transport: &T,
        now_ms: u64,
    ) -> Result<SyncReport, TnError> {
        let account_id = vault.account_id();

        // ─── Step 1: Fetch & Verify Checkpoint (S13 Guard) ──────────────────────
        let checkpoint = transport
            .get_checkpoint()
            .map_err(|_| TnError::Unavailable)?; // Scenario S13: NEVER fall back to null/cached root!

        verify_checkpoint(
            &checkpoint,
            &self.server_vk,
            &self.policy,
            self.last_checkpoint_size,
            self.last_checkpoint_ts,
            now_ms,
        )?;

        self.last_checkpoint_size = checkpoint.size;
        self.last_checkpoint_ts = checkpoint.timestamp_ms;

        // ─── Step 2: Fetch & Verify Account Head Consistency (S14 Guard) ────────
        let head = transport.get_account_head(&account_id)?;
        let local_report = vault.verify_local()?;
        let local_size = local_report.total_ops as u64;

        let stored_size = vault
            .storage()
            .get_metadata("last_verified_tree_size")?
            .and_then(|b| {
                if b.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&b);
                    Some(u64::from_le_bytes(arr))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let stored_root = vault
            .storage()
            .get_metadata("last_verified_account_root")?
            .and_then(|b| {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    Some(MerkleRoot::from_bytes(arr))
                } else {
                    None
                }
            });

        // Scenario S6: Rollback guard
        let is_rollback = if stored_size > 0 {
            head.tree_size < stored_size
        } else {
            head.tree_size < local_size
        };
        if is_rollback {
            return Err(TnError::Rollback);
        }

        let new_root = MerkleRoot::from_bytes(head.root_hash);

        let after_idx = if stored_size > 0 {
            if head.tree_size > stored_size {
                let proof_resp =
                    transport.get_account_consistency_proof(&account_id, stored_size)?;
                let consistency_proof = ConsistencyProof {
                    old_size: proof_resp.old_size,
                    new_size: proof_resp.new_size,
                    path: proof_resp.path,
                };
                let old_root = stored_root.ok_or_else(|| {
                    TnError::Internal("Missing stored root for non-zero stored size".into())
                })?;
                verify_consistency(&old_root, &new_root, &consistency_proof)?;
            } else if head.tree_size == stored_size {
                let expected_root = stored_root.ok_or_else(|| {
                    TnError::Internal("Missing stored root for non-zero stored size".into())
                })?;
                if head.root_hash != *expected_root.as_bytes() {
                    return Err(TnError::RootMismatch);
                }
            }
            Some(stored_size - 1)
        } else if local_size > 0 {
            if head.tree_size > local_size {
                let proof_resp =
                    transport.get_account_consistency_proof(&account_id, local_size)?;
                let consistency_proof = ConsistencyProof {
                    old_size: proof_resp.old_size,
                    new_size: proof_resp.new_size,
                    path: proof_resp.path,
                };
                let local_ops = vault.get_all_ops_internal()?;
                let mut local_tree = tn_merkle::MerkleTree::new();
                for (id, _) in local_ops {
                    local_tree.append_leaf_hash(*id.as_bytes());
                }
                let old_root = local_tree.root();
                verify_consistency(&old_root, &new_root, &consistency_proof)?;
            }
            Some(local_size - 1)
        } else {
            None
        };

        // ─── Step 3: Fetch & Verify Ops ────────────────────────────────────────
        let fetch_threshold = if stored_size > 0 {
            stored_size
        } else {
            local_size
        };

        let mut ops_pulled = 0;
        if head.tree_size > fetch_threshold {
            let fetch_resp = transport.fetch_ops(&account_id, after_idx, 1000)?;
            ops_pulled = fetch_resp.ops.len();

            if stored_size == 0 && local_size == 0 && head.tree_size > 0 {
                let mut initial_tree = tn_merkle::MerkleTree::new();
                for (op, _) in &fetch_resp.ops {
                    let op_id = op.compute_op_id()?;
                    initial_tree.append_leaf_hash(*op_id.as_bytes());
                }
                if initial_tree.root().as_bytes() != &head.root_hash {
                    return Err(TnError::RootMismatch);
                }
            }

            for (op, _) in fetch_resp.ops {
                let op_id = op.compute_op_id()?;
                vault.ingest_verified_op(&op, op_id)?;
            }
        }

        // Persist newly verified canonical tree size and root
        vault
            .storage()
            .set_metadata("last_verified_tree_size", &head.tree_size.to_le_bytes())?;
        vault
            .storage()
            .set_metadata("last_verified_account_root", &head.root_hash)?;

        let final_report = vault.verify_local()?;

        Ok(SyncReport {
            ops_pushed: 0,
            receipts_collected: 0,
            ops_pulled,
            total_verified_ops: final_report.total_ops,
            checkpoint_log_size: checkpoint.size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tn_proto::AccountRegisterReq;
    use tn_server::Server;
    use tn_tlog::Cosignature;

    /// Adapter implementing SyncTransport directly for `tn_server::Server` in-memory tests.
    struct ServerTestTransport<'a> {
        server: &'a mut Server,
        device_vk: VerifyingKeys,
        now_ms: u64,
    }

    impl<'a> SyncTransport for ServerTestTransport<'a> {
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

    fn make_test_fixture() -> (Server, WitnessPolicy, [u8; 32], [u8; 32]) {
        let server = Server::in_memory("test.trustnotes.origin".to_string()).unwrap();
        let w1 = [0x11u8; 32];
        let w2 = [0x22u8; 32];
        let policy = WitnessPolicy {
            threshold: 2,
            pinned_witnesses: vec![w1, w2],
            max_age_seconds: 300,
        };
        (server, policy, w1, w2)
    }

    #[test]
    fn test_sync_s13_fetch_failure_no_fallback() {
        let (mut server, policy, _w1, _w2) = make_test_fixture();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("sync-pass")).unwrap();

        let mut client = SyncClient::new(
            "test.trustnotes.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let transport = ServerTestTransport {
            device_vk: vault.signing_keys_ref().verifying_keys(),
            now_ms: 1_700_000_000_000,
            server: &mut server,
        };

        // Server has not published any checkpoint yet -> S13: must fail closed with TnError::Unavailable
        let res = client.pull_and_verify(&mut vault, &transport, 1_700_000_000_000);
        assert!(matches!(res, Err(TnError::Unavailable)));
    }

    #[test]
    fn test_sync_s8_insufficient_witnesses() {
        let (mut server, policy, w1, _w2) = make_test_fixture();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("sync-pass")).unwrap();

        let mut client = SyncClient::new(
            "test.trustnotes.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let now_ms = 1_700_000_000_000u64;
        let mut cp = server.publish_epoch(now_ms).unwrap();
        // Add only 1 cosignature when threshold is 2
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });

        // Set checkpoint in server
        let transport = ServerTestTransport {
            device_vk: vault.signing_keys_ref().verifying_keys(),
            now_ms,
            server: &mut server,
        };

        // S8: must reject with WitnessPolicy
        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::WitnessPolicy)));
    }

    #[test]
    fn test_sync_push_and_pull_happy_path() {
        let (mut server, policy, w1, w2) = make_test_fixture();
        let dir = tempdir().unwrap();
        let db1_path = dir.path().join("vault1.db");
        let (mut vault1, phrase) = Vault::create_new(&db1_path, Some("sync-pass")).unwrap();

        let account_id = vault1.account_id();
        let now_ms = 1_700_000_000_000u64;

        // Register account on server with initial device
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

        // Vault1 creates 2 notes
        let _ = vault1
            .new_note("Note 1", "Body 1", vec!["tag1".into()], None)
            .unwrap();
        let _ = vault1
            .new_note("Note 2", "Body 2", vec!["tag2".into()], None)
            .unwrap();

        let mut client = SyncClient::new(
            "test.trustnotes.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let device1_vk = vault1.signing_keys_ref().verifying_keys();

        // Push ops to server
        let mut transport = ServerTestTransport {
            device_vk: device1_vk.clone(),
            now_ms: now_ms + 1000,
            server: &mut server,
        };

        let receipts = client
            .push_ops(&vault1, &mut transport, now_ms + 1000)
            .unwrap();
        assert_eq!(receipts.len(), 2);

        // Server publishes epoch and attaches witness cosignatures
        let mut cp = server.publish_epoch(now_ms + 2000).unwrap();
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms + 2000,
            sig_ed: [0u8; 64],
        });
        cp.cosignatures.push(Cosignature {
            witness_key_id: w2,
            timestamp_ms: now_ms + 2000,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp);

        // Recover vault2 from recovery phrase (simulating 2nd device sync)
        let db2_path = dir.path().join("vault2.db");
        let mut vault2 = Vault::recover_from_phrase(&db2_path, &phrase, Some("sync-pass")).unwrap();
        assert_eq!(vault2.account_id(), account_id);
        assert_eq!(vault2.list_notes(false).unwrap().len(), 0);

        // Pull and verify on vault2
        let pull_transport = ServerTestTransport {
            device_vk: device1_vk,
            now_ms: now_ms + 2100,
            server: &mut server,
        };

        let report = client
            .pull_and_verify(&mut vault2, &pull_transport, now_ms + 2100)
            .unwrap();
        assert_eq!(report.ops_pulled, 2);
        assert_eq!(report.total_verified_ops, 2);

        // Vault2 can read the materialized notes
        let notes = vault2.list_notes(false).unwrap();
        assert_eq!(notes.len(), 2);
    }
}
