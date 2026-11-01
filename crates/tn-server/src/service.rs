#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Unified server request handler dispatching `/v1/` routes.

use rusqlite::params;
use tn_crypto::{SigningKeys, VerifyingKeys};
use tn_oplog::Op;
use tn_proto::{
    AccountHeadResp, AccountRegisterReq, AuthHeaders, ConsistencyProofResp, InclusionProofResp,
    OpFetchResp, OpSubmitReq, OpSubmitResp, ServerInfoResp,
};
use tn_tlog::Checkpoint;
use tn_types::{cbor, Id32, TnError, PROTOCOL_VERSION};

use crate::db::ServerDb;
use crate::epoch_publisher::EpochPublisher;
use crate::sequencer::Sequencer;

/// Unified sync server engine.
pub struct Server {
    db: ServerDb,
    sequencer: Sequencer,
    publisher: EpochPublisher,
    server_keys: SigningKeys,
    origin: String,
    latest_checkpoint: Option<Checkpoint>,
}

impl Server {
    /// Creates a new in-memory Server instance for testing.
    pub fn in_memory(origin: String) -> Result<Self, TnError> {
        let db = ServerDb::in_memory()?;
        let ed_seed = [42u8; 32];
        let pq_seed = [43u8; 32];
        let server_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        let sequencer = Sequencer::new(SigningKeys::from_seeds(&ed_seed, &pq_seed));
        let publisher =
            EpochPublisher::new(SigningKeys::from_seeds(&ed_seed, &pq_seed), origin.clone());

        Ok(Self {
            db,
            sequencer,
            publisher,
            server_keys,
            origin,
            latest_checkpoint: None,
        })
    }

    /// Access to server verifying keys.
    #[must_use]
    pub fn verifying_keys(&self) -> VerifyingKeys {
        self.server_keys.verifying_keys()
    }

    /// Access to database.
    #[must_use]
    pub fn db(&self) -> &ServerDb {
        &self.db
    }

    /// Access to sequencer.
    pub fn sequencer_mut(&mut self) -> &mut Sequencer {
        &mut self.sequencer
    }

    /// Access to publisher.
    pub fn publisher_mut(&mut self) -> &mut EpochPublisher {
        &mut self.publisher
    }

    /// Handles `POST /v1/accounts` (Register account & initial device).
    pub fn register_account(
        &mut self,
        req: &AccountRegisterReq,
        now_ms: u64,
    ) -> Result<(), TnError> {
        let created_bucket = now_ms / 3_600_000; // Quantized hourly

        let mut bundle = Vec::with_capacity(32 + req.aik_pq_pub.len());
        bundle.extend_from_slice(&req.aik_ed_pub);
        bundle.extend_from_slice(&req.aik_pq_pub);

        self.db
            .insert_account(req.account_id.as_bytes(), &bundle, created_bucket)?;

        // Enroll initial device
        if let Some(op) = &req.initial_op {
            let dev_id = op.device_id;
            let cert_cbor = op.to_cbor()?;
            self.db
                .insert_device(dev_id.as_bytes(), req.account_id.as_bytes(), &cert_cbor)?;

            // Sequence initial op
            let submit_req = OpSubmitReq {
                ops: vec![op.clone()],
                receipt_requested: true,
            };
            let _ = self
                .sequencer
                .sequence_batch(&self.db, &submit_req, now_ms)?;
        } else {
            // Default initial device is account_id
            self.db
                .insert_device(req.account_id.as_bytes(), req.account_id.as_bytes(), &[])?;
        }

        Ok(())
    }

    /// Sets the latest checkpoint directly (e.g. after attaching witness cosignatures).
    pub fn set_latest_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.latest_checkpoint = Some(checkpoint);
    }

    /// Handles `POST /v1/ops` (Submit batch of ops with X-TN-* authentication).
    pub fn submit_ops(
        &mut self,
        req: &OpSubmitReq,
        headers: &AuthHeaders,
        device_vk: &VerifyingKeys,
        now_ms: u64,
    ) -> Result<OpSubmitResp, TnError> {
        // 1. Verify anti-replay nonce
        let expires_at = now_ms + 300_000; // 5 min TTL
        self.db.check_and_record_nonce(
            headers.device_id.as_bytes(),
            &headers.nonce,
            expires_at,
            now_ms,
        )?;

        // 2. Verify request signature
        let req_bytes = cbor::encode_canonical(req)?;
        tn_proto::verify_request(
            "POST",
            "/v1/ops",
            "",
            &req_bytes,
            headers,
            device_vk,
            now_ms,
            &self.origin,
        )?;

        // 3. Sequence batch
        self.sequencer.sequence_batch(&self.db, req, now_ms)
    }

    /// Handles `GET /v1/ops?after=&limit=`.
    pub fn fetch_ops(
        &self,
        account_id: &Id32,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<OpFetchResp, TnError> {
        let mut ops = Vec::new();

        if let Some(after) = after_index {
            let mut stmt = self
                .db
                .conn()
                .prepare("SELECT idx, op_bytes FROM ops WHERE account_id = ?1 AND idx > ?2 ORDER BY idx ASC LIMIT ?3")
                .map_err(|e| TnError::Internal(e.to_string()))?;

            let rows = stmt
                .query_map(
                    params![account_id.as_bytes().as_slice(), after as i64, limit as i64],
                    |row| {
                        let idx: i64 = row.get(0)?;
                        let op_bytes: Vec<u8> = row.get(1)?;
                        Ok((idx as u64, op_bytes))
                    },
                )
                .map_err(|e| TnError::Internal(e.to_string()))?;

            for item in rows {
                let (idx, bytes) = item.map_err(|e| TnError::Internal(e.to_string()))?;
                let op = Op::from_cbor(&bytes)?;
                ops.push((op, idx));
            }
        } else {
            let mut stmt = self
                .db
                .conn()
                .prepare(
                    "SELECT idx, op_bytes FROM ops WHERE account_id = ?1 ORDER BY idx ASC LIMIT ?2",
                )
                .map_err(|e| TnError::Internal(e.to_string()))?;

            let rows = stmt
                .query_map(
                    params![account_id.as_bytes().as_slice(), limit as i64],
                    |row| {
                        let idx: i64 = row.get(0)?;
                        let op_bytes: Vec<u8> = row.get(1)?;
                        Ok((idx as u64, op_bytes))
                    },
                )
                .map_err(|e| TnError::Internal(e.to_string()))?;

            for item in rows {
                let (idx, bytes) = item.map_err(|e| TnError::Internal(e.to_string()))?;
                let op = Op::from_cbor(&bytes)?;
                ops.push((op, idx));
            }
        }

        // Get tree size
        let head = self.get_account_head(account_id)?;
        Ok(OpFetchResp {
            ops,
            account_tree_size: head.tree_size,
        })
    }

    /// Handles `GET /v1/account/head`.
    pub fn get_account_head(&self, account_id: &Id32) -> Result<AccountHeadResp, TnError> {
        let mut stmt = self
            .db
            .conn()
            .prepare("SELECT size, root FROM account_heads WHERE account_id = ?1")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let mut rows = stmt
            .query(params![account_id.as_bytes().as_slice()])
            .map_err(|e| TnError::Internal(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| TnError::Internal(e.to_string()))? {
            let size: i64 = row.get(0).map_err(|e| TnError::Internal(e.to_string()))?;
            let root_bytes: Vec<u8> = row.get(1).map_err(|e| TnError::Internal(e.to_string()))?;
            let mut root = [0u8; 32];
            root.copy_from_slice(&root_bytes);

            Ok(AccountHeadResp {
                account_id: *account_id,
                tree_size: size as u64,
                root_hash: root,
            })
        } else {
            Ok(AccountHeadResp {
                account_id: *account_id,
                tree_size: 0,
                root_hash: [0u8; 32],
            })
        }
    }

    /// Handles `GET /v1/account/proof/inclusion?index=`.
    pub fn get_account_inclusion_proof(
        &self,
        account_id: &Id32,
        leaf_index: u64,
    ) -> Result<InclusionProofResp, TnError> {
        let tree = self
            .sequencer
            .get_account_tree(account_id)
            .ok_or_else(|| TnError::Internal("Account tree not initialized".into()))?;

        let proof = tree.inclusion_proof(leaf_index)?;
        Ok(InclusionProofResp {
            leaf_index,
            tree_size: proof.tree_size,
            path: proof.path,
        })
    }

    /// Handles `GET /v1/account/proof/consistency?from=&to=`.
    pub fn get_account_consistency_proof(
        &self,
        account_id: &Id32,
        from_size: u64,
    ) -> Result<ConsistencyProofResp, TnError> {
        let tree = self
            .sequencer
            .get_account_tree(account_id)
            .ok_or_else(|| TnError::Internal("Account tree not initialized".into()))?;

        let proof = tree.consistency_proof(from_size)?;
        Ok(ConsistencyProofResp {
            old_size: proof.old_size,
            new_size: proof.new_size,
            path: proof.path,
        })
    }

    /// Publishes current epoch and stores checkpoint.
    pub fn publish_epoch(&mut self, now_ms: u64) -> Result<Checkpoint, TnError> {
        let epoch = self.sequencer.current_epoch();
        let cp = self.publisher.publish_epoch(&self.db, epoch, now_ms)?;
        self.latest_checkpoint = Some(cp.clone());
        self.sequencer.set_epoch(epoch + 1);
        Ok(cp)
    }

    /// Handles `GET /v1/log/checkpoint`.
    #[must_use]
    pub fn get_checkpoint(&self) -> Option<&Checkpoint> {
        self.latest_checkpoint.as_ref()
    }

    /// Handles `GET /v1/server-info`.
    #[must_use]
    pub fn server_info(&self) -> ServerInfoResp {
        let vk = self.verifying_keys();
        ServerInfoResp {
            protocol_version: PROTOCOL_VERSION,
            server_ed25519_pub: vk.ed25519_bytes,
            server_mldsa65_pub: vk.mldsa65_bytes,
            witness_list: vec![],
            current_epoch: self.sequencer.current_epoch(),
            mmd_epochs: 10,
        }
    }
}
