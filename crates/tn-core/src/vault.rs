#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Vault engine: high-level encrypted note operations and local transparency pipeline.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tn_crypto::kem::{HybridKemPrivateKey, HybridKemPublicKey};
use tn_crypto::labels::LABEL_SIG_OP;
use tn_crypto::{
    decode_recovery_key, derive_account_id, derive_account_root, derive_aik_ed_seed,
    derive_aik_pq_seed, derive_device_id, derive_lsk_from_passphrase, derive_vault_key,
    encode_recovery_key, open_note_payload, seal_note_payload, unwrap_note_key, wrap_note_key,
    AccountRoot, LocalStorageKey, NoteKey, RecoveryKey, SigningKeys, VaultKey, VerifyingKeys,
};
use tn_oplog::{
    compute_ct_hash, compute_op_aad, compute_op_id, ConflictStatus, Hlc, LaneRegistry,
    NoteDagTracker, Op, OpHeader, Payload,
};
use tn_proto::{
    DeviceCertificate, DeviceGossip, DeviceRevokePayload, EnrollmentPackage, KeyRotatePayload,
};
use tn_types::{cbor, Id16, Id32, OpKind, TnError};

use crate::search::SearchIndex;
use crate::storage::Storage;

/// Brief summary of a note for list displays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteSummary {
    /// Object identifier.
    pub object_id: Id16,
    /// Identifier of the latest active head operation.
    pub head_op_id: Id32,
    /// Note title.
    pub title: String,
    /// Associated tags.
    pub tags: Vec<String>,
    /// Note status: "active", "conflicted", "trashed", "shredded".
    pub status: String,
    /// Last update timestamp (Unix ms).
    pub updated_at: u64,
}

/// Full details of a note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteDetail {
    /// Summary metadata.
    pub summary: NoteSummary,
    /// Markdown body text.
    pub body_md: String,
    /// History of operations modifying this note.
    pub history: Vec<Id32>,
}

/// Result report from local integrity verification (`verify --local`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Total number of operations evaluated.
    pub total_ops: usize,
    /// Number of successfully verified operations.
    pub verified_ops: usize,
    /// Whether all cryptographic and structural invariants hold.
    pub valid: bool,
}

/// The core local vault manager.
pub struct Vault {
    storage: Storage,
    account_id: Id32,
    device_id: Id32,
    account_root: AccountRoot,
    vault_key: VaultKey,
    previous_vault_keys: Vec<VaultKey>,
    signing_keys: SigningKeys,
    lsk: LocalStorageKey,
    lanes: LaneRegistry,
    search_index: SearchIndex,
    last_hlc: Option<Hlc>,
}

impl Vault {
    /// Creates a brand new vault, generating a 24-word recovery phrase.
    ///
    /// # Errors
    /// Returns `TnError` if crypto or storage initialization fails.
    pub fn create_new(db_path: &Path, passphrase: Option<&str>) -> Result<(Self, String), TnError> {
        let storage = Storage::open(db_path)?;

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| TnError::Internal(format!("Entropy generation failed: {e}")))?;
        let rk = RecoveryKey::from_bytes(entropy);
        let phrase = encode_recovery_key(&rk);

        let ar = derive_account_root(&rk);
        let vk = derive_vault_key(&ar);

        let ed_seed = derive_aik_ed_seed(&ar);
        let pq_seed = derive_aik_pq_seed(&ar);
        let signing_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        let verifying_keys = signing_keys.verifying_keys();

        let account_id =
            derive_account_id(&verifying_keys.ed25519_bytes, &verifying_keys.mldsa65_bytes);
        let device_id = account_id; // Initial device shares AIK identity root

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| TnError::Internal(format!("Salt generation failed: {e}")))?;

        let p = passphrase.unwrap_or("");
        let lsk = derive_lsk_from_passphrase(p, &salt)?;

        // Save metadata
        storage.set_metadata("account_id", account_id.as_bytes())?;
        storage.set_metadata("device_id", device_id.as_bytes())?;
        storage.set_metadata("salt", &salt)?;

        // Save encrypted keyring slots
        storage.set_keyring_slot("account_root", ar.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("vault_key", vk.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("ed_seed", &ed_seed, &lsk)?;
        storage.set_keyring_slot("pq_seed", &pq_seed, &lsk)?;

        let vault = Self {
            storage,
            account_id,
            device_id,
            account_root: ar,
            vault_key: vk,
            previous_vault_keys: Vec::new(),
            signing_keys,
            lsk,
            lanes: LaneRegistry::new(),
            search_index: SearchIndex::new(),
            last_hlc: None,
        };

        Ok((vault, phrase))
    }

    /// Opens an existing vault from disk.
    ///
    /// # Errors
    /// Returns `TnError` if file cannot be opened, passphrase fails, or slots are missing.
    pub fn open(db_path: &Path, passphrase: Option<&str>) -> Result<Self, TnError> {
        let storage = Storage::open(db_path)?;

        let acc_bytes = storage
            .get_metadata("account_id")?
            .ok_or_else(|| TnError::Internal("Missing account_id metadata".into()))?;
        let mut acc_arr = [0u8; 32];
        acc_arr.copy_from_slice(&acc_bytes);
        let account_id = Id32::from_bytes(acc_arr);

        let dev_bytes = storage
            .get_metadata("device_id")?
            .ok_or_else(|| TnError::Internal("Missing device_id metadata".into()))?;
        let mut dev_arr = [0u8; 32];
        dev_arr.copy_from_slice(&dev_bytes);
        let device_id = Id32::from_bytes(dev_arr);

        let salt_bytes = storage
            .get_metadata("salt")?
            .ok_or_else(|| TnError::Internal("Missing salt metadata".into()))?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        let p = passphrase.unwrap_or("");
        let lsk = derive_lsk_from_passphrase(p, &salt)?;

        let ar_bytes = storage
            .get_keyring_slot("account_root", &lsk)?
            .ok_or_else(|| TnError::Internal("Missing account_root in keyring".into()))?;
        let mut ar_arr = [0u8; 32];
        ar_arr.copy_from_slice(&ar_bytes);
        let ar = AccountRoot::from_bytes(ar_arr);

        let vk_bytes = storage
            .get_keyring_slot("vault_key", &lsk)?
            .ok_or_else(|| TnError::Internal("Missing vault_key in keyring".into()))?;
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(&vk_bytes);
        let vk = VaultKey::from_bytes(vk_arr);

        let ed_seed = storage
            .get_keyring_slot("ed_seed", &lsk)?
            .ok_or_else(|| TnError::Internal("Missing ed_seed in keyring".into()))?;
        let mut ed_arr = [0u8; 32];
        ed_arr.copy_from_slice(&ed_seed);

        let pq_seed = storage
            .get_keyring_slot("pq_seed", &lsk)?
            .ok_or_else(|| TnError::Internal("Missing pq_seed in keyring".into()))?;
        let mut pq_arr = [0u8; 32];
        pq_arr.copy_from_slice(&pq_seed);

        let signing_keys = SigningKeys::from_seeds(&ed_arr, &pq_arr);

        let mut previous_vault_keys = Vec::new();
        let mut idx = 0;
        while let Ok(Some(archived_bytes)) =
            storage.get_keyring_slot(&format!("vault_key_archived_{idx}"), &lsk)
        {
            if archived_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&archived_bytes);
                previous_vault_keys.push(VaultKey::from_bytes(arr));
            }
            idx += 1;
        }

        let mut vault = Self {
            storage,
            account_id,
            device_id,
            account_root: ar,
            vault_key: vk,
            previous_vault_keys,
            signing_keys,
            lsk,
            lanes: LaneRegistry::new(),
            search_index: SearchIndex::new(),
            last_hlc: None,
        };

        vault.rebuild_state()?;
        Ok(vault)
    }

    /// Rebuilds in-memory lane tracker and search index from stored database ops.
    fn rebuild_state(&mut self) -> Result<(), TnError> {
        let ops = self.storage.get_all_ops()?;
        for (op_id, op) in ops {
            if op.kind == OpKind::DeviceRevoke {
                if let Ok(payload) = cbor::decode_canonical::<DeviceRevokePayload>(&op.ct) {
                    self.lanes.revoke_device(payload.target_device_id);
                }
            }
            self.lanes.record_op(&op, op_id)?;
            self.last_hlc = Some(match self.last_hlc {
                Some(prev) => Hlc::update(&prev, &op.hlc),
                None => op.hlc,
            });
        }

        // Rebuild search index from materialized notes
        let notes = self.storage.list_materialized_notes(&self.lsk)?;
        for (obj_id, _, status, payload) in notes {
            if status == "active" || status == "conflicted" {
                self.search_index.index_note(
                    obj_id,
                    &payload.title,
                    &payload.body_md,
                    &payload.tags,
                );
            }
        }
        Ok(())
    }

    /// Creates a new note in the vault.
    ///
    /// # Errors
    /// Returns `TnError` if op generation, encryption, or storage fails.
    pub fn new_note(
        &mut self,
        title: &str,
        body_md: &str,
        tags: Vec<String>,
        notebook_id: Option<Id16>,
    ) -> Result<Id16, TnError> {
        let mut obj_bytes = [0u8; 16];
        getrandom::getrandom(&mut obj_bytes)
            .map_err(|e| TnError::Internal(format!("Entropy failed: {e}")))?;
        let object_id = Id16::from_bytes(obj_bytes);

        let mut nk_bytes = [0u8; 32];
        getrandom::getrandom(&mut nk_bytes)
            .map_err(|e| TnError::Internal(format!("Entropy failed: {e}")))?;
        let nk = NoteKey::from_bytes(nk_bytes);

        let nk_wrap = wrap_note_key(&self.vault_key, object_id, &nk)?;

        let now_ms = Hlc::current_physical_ms();
        let payload = Payload {
            schema_v: 1,
            title: title.to_string(),
            body_md: body_md.to_string(),
            tags,
            notebook_id,
            flags: 0,
            created_at: now_ms,
            updated_at: now_ms,
            attachments: Vec::new(),
        };

        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let aad = compute_op_aad(
            1,
            self.account_id,
            self.device_id,
            lane_seq,
            object_id,
            OpKind::Put,
        )?;

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| TnError::Internal(format!("Payload serialize error: {e}")))?;
        let ct_with_nonce = seal_note_payload(&nk, &aad, &payload_bytes)?;

        let (nonce_bytes, ct) = ct_with_nonce.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let ct_hash = compute_ct_hash(ct);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Put,
            object_id,
            nk_wrap: Some(nk_wrap),
            nonce,
            deps: vec![],
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;

        // Sign header digest with domain separation
        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Put,
            object_id,
            nk_wrap: header.nk_wrap,
            nonce,
            deps: header.deps,
            ct: ct.to_vec(),
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;
        self.storage
            .save_materialized_note(object_id, op_id, "active", &payload, &self.lsk)?;
        self.search_index
            .index_note(object_id, &payload.title, &payload.body_md, &payload.tags);

        Ok(object_id)
    }

    /// Edits an existing note, superseding all current active heads in `deps`.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn edit_note(
        &mut self,
        object_id: Id16,
        title: &str,
        body_md: &str,
        tags: Vec<String>,
    ) -> Result<Id32, TnError> {
        let (nk, prev_created_at, heads) = self.get_note_internal(object_id)?;

        let now_ms = Hlc::current_physical_ms();
        let payload = Payload {
            schema_v: 1,
            title: title.to_string(),
            body_md: body_md.to_string(),
            tags,
            notebook_id: None,
            flags: 0,
            created_at: prev_created_at,
            updated_at: now_ms,
            attachments: Vec::new(),
        };

        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let aad = compute_op_aad(
            1,
            self.account_id,
            self.device_id,
            lane_seq,
            object_id,
            OpKind::Put,
        )?;

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| TnError::Internal(format!("Payload serialize error: {e}")))?;
        let ct_with_nonce = seal_note_payload(&nk, &aad, &payload_bytes)?;

        let (nonce_bytes, ct) = ct_with_nonce.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let ct_hash = compute_ct_hash(ct);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Put,
            object_id,
            nk_wrap: None, // Key already wrapped in initial Put
            nonce,
            deps: heads,
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;

        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Put,
            object_id,
            nk_wrap: None,
            nonce,
            deps: header.deps,
            ct: ct.to_vec(),
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;
        self.storage
            .save_materialized_note(object_id, op_id, "active", &payload, &self.lsk)?;
        self.search_index
            .index_note(object_id, &payload.title, &payload.body_md, &payload.tags);

        Ok(op_id)
    }

    /// Unwraps a wrapped NoteKey attempting current and historical vault keys (ADR-0002).
    fn unwrap_note_key_any(&self, object_id: Id16, wrapped: &[u8]) -> Result<NoteKey, TnError> {
        if let Ok(key) = unwrap_note_key(&self.vault_key, object_id, wrapped) {
            return Ok(key);
        }
        for old_vk in &self.previous_vault_keys {
            if let Ok(key) = unwrap_note_key(old_vk, object_id, wrapped) {
                return Ok(key);
            }
        }
        unwrap_note_key(&self.vault_key, object_id, wrapped)
    }

    /// Internal helper to retrieve NoteKey, creation time, and current active heads for an object.
    fn get_note_internal(&self, object_id: Id16) -> Result<(NoteKey, u64, Vec<Id32>), TnError> {
        let ops = self.storage.get_ops_for_object(object_id)?;
        if ops.is_empty() {
            return Err(TnError::Internal("Note not found".into()));
        }

        let mut nk = None;
        let mut tracker = NoteDagTracker::new(object_id);

        for (op_id, op) in &ops {
            tracker.add_op(*op_id, op);
            if nk.is_none() {
                if let Some(wrapped) = &op.nk_wrap {
                    let key = self.unwrap_note_key_any(object_id, wrapped)?;
                    nk = Some(key);
                }
            }
        }

        let key =
            nk.ok_or_else(|| TnError::Internal("Note key wrap not found in history".into()))?;

        // Read created_at from first op payload
        let first_op = &ops[0].1;
        let aad = compute_op_aad(
            first_op.v,
            first_op.account_id,
            first_op.device_id,
            first_op.lane_seq,
            first_op.object_id,
            first_op.kind,
        )?;
        let mut full_ct = Vec::with_capacity(24 + first_op.ct.len());
        full_ct.extend_from_slice(&first_op.nonce);
        full_ct.extend_from_slice(&first_op.ct);
        let pt = open_note_payload(&key, &aad, &full_ct)?;
        let p: Payload = cbor::decode_canonical(&pt).or_else(|_| {
            serde_json::from_slice(&pt)
                .map_err(|e| TnError::Internal(format!("Decode payload error: {e}")))
        })?;
        let created_at = p.created_at;

        let heads = match tracker.status() {
            ConflictStatus::Single(h) => vec![h],
            ConflictStatus::Conflicted { heads } => heads,
            ConflictStatus::Deleted(h) => vec![h],
        };

        Ok((key, created_at, heads))
    }

    /// Soft-deletes a note (marks trashed, retains history).
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn delete_note(&mut self, object_id: Id16) -> Result<Id32, TnError> {
        let (_, _, heads) = self.get_note_internal(object_id)?;

        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let ct_hash = compute_ct_hash(&[]);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Delete,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: heads,
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;

        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Delete,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: header.deps,
            ct: vec![],
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;
        self.search_index.remove_note(object_id);

        Ok(op_id)
    }

    /// Crypto-shreds a note: client drops NK locally and issues kind 6 shred op.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn shred_note(&mut self, object_id: Id16) -> Result<Id32, TnError> {
        let (_, _, heads) = self.get_note_internal(object_id)?;

        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let ct_hash = compute_ct_hash(&[]);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Shred,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: heads,
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;

        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::Shred,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: header.deps,
            ct: vec![],
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;
        self.search_index.remove_note(object_id);

        Ok(op_id)
    }

    /// Lists note summaries from local materialized view.
    ///
    /// # Errors
    /// Returns `TnError` on read failure.
    pub fn list_notes(&self, include_trashed: bool) -> Result<Vec<NoteSummary>, TnError> {
        let rows = self.storage.list_materialized_notes(&self.lsk)?;
        let mut summaries = Vec::new();
        for (object_id, head_op_id, status, payload) in rows {
            if !include_trashed && (status == "trashed" || status == "shredded") {
                continue;
            }
            summaries.push(NoteSummary {
                object_id,
                head_op_id,
                title: payload.title,
                tags: payload.tags,
                status,
                updated_at: payload.updated_at,
            });
        }
        Ok(summaries)
    }

    /// Fetches a full note including decrypted markdown body.
    ///
    /// # Errors
    /// Returns `TnError` if not found or decryption fails.
    pub fn get_note(&self, object_id: Id16) -> Result<NoteDetail, TnError> {
        let (nk, _, _) = self.get_note_internal(object_id)?;
        let ops = self.storage.get_ops_for_object(object_id)?;

        let (latest_id, latest_op) = ops
            .last()
            .ok_or_else(|| TnError::Internal("Note has no history".into()))?;

        let history: Vec<Id32> = ops.iter().map(|(id, _)| *id).collect();

        let aad = compute_op_aad(
            latest_op.v,
            latest_op.account_id,
            latest_op.device_id,
            latest_op.lane_seq,
            latest_op.object_id,
            latest_op.kind,
        )?;

        let mut full_ct = Vec::with_capacity(24 + latest_op.ct.len());
        full_ct.extend_from_slice(&latest_op.nonce);
        full_ct.extend_from_slice(&latest_op.ct);

        let pt = open_note_payload(&nk, &aad, &full_ct)?;
        let payload: Payload = cbor::decode_canonical(&pt).or_else(|_| {
            serde_json::from_slice(&pt)
                .map_err(|e| TnError::Internal(format!("Decode payload error: {e}")))
        })?;

        let summary = NoteSummary {
            object_id,
            head_op_id: *latest_id,
            title: payload.title,
            tags: payload.tags,
            status: "active".into(),
            updated_at: payload.updated_at,
        };

        Ok(NoteDetail {
            summary,
            body_md: payload.body_md,
            history,
        })
    }

    /// Searches for notes using the in-memory inverted index.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn search(&self, query: &str) -> Result<Vec<NoteSummary>, TnError> {
        let matched_ids = self.search_index.search(query);
        let all_summaries = self.list_notes(false)?;
        let summary_map: HashMap<Id16, NoteSummary> = all_summaries
            .into_iter()
            .map(|s| (s.object_id, s))
            .collect();

        let mut results = Vec::new();
        for id in matched_ids {
            if let Some(sum) = summary_map.get(&id) {
                results.push(sum.clone());
            }
        }
        Ok(results)
    }

    /// Executes complete local verification pipeline across all stored operations.
    ///
    /// Validates:
    /// - OpHeader canonical serialization & `op_id` integrity
    /// - `ct_hash = SHA-256(ct)`
    /// - Hybrid signatures (Ed25519 + ML-DSA-65) over `LABEL_SIG_OP || op_id`
    /// - Per-device lane continuity (`lane_seq` and `lane_prev`)
    /// - Note Key unwrapping and AEAD payload decryption
    ///
    /// # Errors
    /// Fails closed: returns typed `TnError` (e.g. `CiphertextTampered`, `BadSignature`, `OrderViolation`)
    /// if any operation fails verification.
    pub fn verify_local(&self) -> Result<VerificationReport, TnError> {
        let ops = self.storage.get_all_ops()?;
        let mut lanes = LaneRegistry::new();
        let mut note_keys: HashMap<Id16, NoteKey> = HashMap::new();
        let mut device_keys_map: HashMap<Id32, VerifyingKeys> = HashMap::new();

        // 0. Register known device verifying keys
        let ed_seed = derive_aik_ed_seed(&self.account_root);
        let pq_seed = derive_aik_pq_seed(&self.account_root);
        let aik_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        device_keys_map.insert(self.account_id, aik_keys.verifying_keys());
        device_keys_map.insert(self.device_id, self.signing_keys.verifying_keys());

        // Pre-populate enrolled devices from DeviceAdd ops
        for (_, op) in &ops {
            if op.kind == OpKind::DeviceAdd {
                if let Ok(cert) = cbor::decode_canonical::<DeviceCertificate>(&op.ct) {
                    device_keys_map.insert(cert.device_id, cert.device_verifying_keys());
                }
            }
        }

        let total_ops = ops.len();
        let mut verified_ops = 0;

        for (op_id, op) in &ops {
            // 1. Verify ct_hash
            let computed_ct_hash = compute_ct_hash(&op.ct);
            let header = op.to_header();
            if header.ct_hash != computed_ct_hash {
                return Err(TnError::CiphertextTampered);
            }

            // 2. Verify op_id
            let computed_op_id = compute_op_id(&header)?;
            if computed_op_id != *op_id {
                return Err(TnError::CiphertextTampered);
            }

            // 3. Verify hybrid signatures using author device verifying keys
            let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
            sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
            sig_msg.extend_from_slice(op_id.as_bytes());

            let hybrid_sig = tn_crypto::HybridSignature {
                ed25519: op.sig_ed,
                ml_dsa: op.sig_pq.clone(),
            };
            let author_vk = device_keys_map
                .get(&op.device_id)
                .ok_or(TnError::BadSignature)?;
            author_vk.verify(&sig_msg, &hybrid_sig)?;

            // 4. Verify lane continuity
            lanes.record_op(op, *op_id)?;

            // 5. If Put with nk_wrap, unwrap NoteKey and verify payload AEAD
            if op.kind == OpKind::Put {
                if let Some(wrapped) = &op.nk_wrap {
                    let nk = self.unwrap_note_key_any(op.object_id, wrapped)?;
                    note_keys.insert(op.object_id, nk);
                }

                if let Some(nk) = note_keys.get(&op.object_id) {
                    let aad = compute_op_aad(
                        op.v,
                        op.account_id,
                        op.device_id,
                        op.lane_seq,
                        op.object_id,
                        op.kind,
                    )?;
                    let mut full_ct = Vec::with_capacity(24 + op.ct.len());
                    full_ct.extend_from_slice(&op.nonce);
                    full_ct.extend_from_slice(&op.ct);

                    open_note_payload(nk, &aad, &full_ct)?;
                }
            }

            verified_ops += 1;
        }

        Ok(VerificationReport {
            total_ops,
            verified_ops,
            valid: true,
        })
    }

    /// Recovers a vault from a 24-word recovery phrase.
    ///
    /// # Errors
    /// Returns `TnError` if phrase decoding or storage fails.
    pub fn recover_from_phrase(
        db_path: &Path,
        phrase: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, TnError> {
        let rk = decode_recovery_key(phrase)?;
        let storage = Storage::open(db_path)?;

        let ar = derive_account_root(&rk);
        let vk = derive_vault_key(&ar);

        let ed_seed = derive_aik_ed_seed(&ar);
        let pq_seed = derive_aik_pq_seed(&ar);
        let signing_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        let verifying_keys = signing_keys.verifying_keys();

        let account_id =
            derive_account_id(&verifying_keys.ed25519_bytes, &verifying_keys.mldsa65_bytes);
        let device_id = account_id;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| TnError::Internal(format!("Salt generation failed: {e}")))?;

        let p = passphrase.unwrap_or("");
        let lsk = derive_lsk_from_passphrase(p, &salt)?;

        storage.set_metadata("account_id", account_id.as_bytes())?;
        storage.set_metadata("device_id", device_id.as_bytes())?;
        storage.set_metadata("salt", &salt)?;

        storage.set_keyring_slot("account_root", ar.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("vault_key", vk.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("ed_seed", &ed_seed, &lsk)?;
        storage.set_keyring_slot("pq_seed", &pq_seed, &lsk)?;

        let mut vault = Self {
            storage,
            account_id,
            device_id,
            account_root: ar,
            vault_key: vk,
            previous_vault_keys: Vec::new(),
            signing_keys,
            lsk,
            lanes: LaneRegistry::new(),
            search_index: SearchIndex::new(),
            last_hlc: None,
        };

        vault.rebuild_state()?;
        Ok(vault)
    }

    /// Accessor for underlying storage.
    #[must_use]
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Accessor for account root key.
    #[must_use]
    pub fn account_root(&self) -> &AccountRoot {
        &self.account_root
    }

    /// Returns the account identifier.
    #[must_use]
    pub fn account_id(&self) -> Id32 {
        self.account_id
    }

    /// Returns the device identifier.
    #[must_use]
    pub fn device_id(&self) -> Id32 {
        self.device_id
    }

    /// Enrolls an additional device under this account (ADR-0002).
    ///
    /// Issues a canonical `DeviceCertificate` cross-signed by the Account Identity Key (AIK),
    /// generates a `DeviceAdd` (kind 3) operation on this device's lane, and stores it.
    ///
    /// # Errors
    /// Returns `TnError` if certificate issuance or op signing fails.
    pub fn enroll_device(
        &mut self,
        new_device_vk: &VerifyingKeys,
        dtk_pub: Vec<u8>,
        expires_at: Option<u64>,
    ) -> Result<(DeviceCertificate, Id32), TnError> {
        let now_ms = Hlc::current_physical_ms();
        let ed_seed = derive_aik_ed_seed(&self.account_root);
        let pq_seed = derive_aik_pq_seed(&self.account_root);
        let aik_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);

        let cert = DeviceCertificate::issue(
            self.account_id,
            new_device_vk,
            dtk_pub,
            now_ms,
            expires_at,
            &aik_keys,
        )?;

        let cert_bytes = cbor::encode_canonical(&cert)?;
        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let ct_hash = compute_ct_hash(&cert_bytes);
        let mut obj_bytes = [0u8; 16];
        obj_bytes.copy_from_slice(&cert.device_id.as_bytes()[..16]);
        let object_id = Id16::from_bytes(obj_bytes);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::DeviceAdd,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;
        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::DeviceAdd,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct: cert_bytes,
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;

        Ok((cert, op_id))
    }

    /// Creates an encrypted `EnrollmentPackage` (Claim C8, X-Wing) for a new device.
    ///
    /// # Errors
    /// Returns `TnError` if certificate issuance or KEM encapsulation fails.
    pub fn create_enrollment_package(
        &mut self,
        new_device_vk: &VerifyingKeys,
        new_device_dtk: &HybridKemPublicKey,
        expires_at: Option<u64>,
    ) -> Result<(EnrollmentPackage, Id32), TnError> {
        let (cert, op_id) =
            self.enroll_device(new_device_vk, new_device_dtk.to_bytes(), expires_at)?;
        let now_ms = Hlc::current_physical_ms();
        let pkg = EnrollmentPackage::seal(
            self.account_id,
            *self.account_root.expose_bytes(),
            cert,
            new_device_dtk,
            self.device_id,
            &self.signing_keys,
            now_ms,
        )?;
        Ok((pkg, op_id))
    }

    /// Accepts and decrypts an `EnrollmentPackage`, initializing the new device vault.
    ///
    /// # Errors
    /// Returns `TnError` if decapsulation, verification, or DB initialization fails.
    #[allow(clippy::too_many_arguments)]
    pub fn from_enrollment_package(
        db_path: &Path,
        passphrase: Option<&str>,
        pkg: &EnrollmentPackage,
        dtk_priv: &HybridKemPrivateKey,
        dtk_pub: &HybridKemPublicKey,
        sender_vk: &VerifyingKeys,
        new_device_ed_seed: [u8; 32],
        new_device_pq_seed: [u8; 32],
    ) -> Result<Self, TnError> {
        let payload = pkg.open(dtk_priv, dtk_pub, sender_vk)?;
        Self::from_enrollment(
            db_path,
            passphrase,
            payload.account_root,
            new_device_ed_seed,
            new_device_pq_seed,
            &payload.device_cert,
        )
    }

    /// Initializes a newly enrolled device vault from an enrollment package.
    ///
    /// # Errors
    /// Returns `TnError` if certificate verification fails or storage initialization fails.
    pub fn from_enrollment(
        db_path: &Path,
        passphrase: Option<&str>,
        account_root_bytes: [u8; 32],
        device_ed_seed: [u8; 32],
        device_pq_seed: [u8; 32],
        device_cert: &DeviceCertificate,
    ) -> Result<Self, TnError> {
        let storage = Storage::open(db_path)?;
        let device_keys = SigningKeys::from_seeds(&device_ed_seed, &device_pq_seed);
        let device_vk = device_keys.verifying_keys();
        let derived_dev_id = derive_device_id(&device_vk.ed25519_bytes, &device_vk.mldsa65_bytes);

        if derived_dev_id != device_cert.device_id {
            return Err(TnError::BadSignature);
        }

        let ar = AccountRoot::from_bytes(account_root_bytes);
        let vk = derive_vault_key(&ar);

        // Verify device certificate using AIK derived from AR
        let ed_seed = derive_aik_ed_seed(&ar);
        let pq_seed = derive_aik_pq_seed(&ar);
        let aik_keys = SigningKeys::from_seeds(&ed_seed, &pq_seed);
        device_cert.verify(&aik_keys.verifying_keys())?;

        let account_id = device_cert.account_id;
        let device_id = device_cert.device_id;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| TnError::Internal(format!("Salt generation failed: {e}")))?;

        let p = passphrase.unwrap_or("");
        let lsk = derive_lsk_from_passphrase(p, &salt)?;

        storage.set_metadata("account_id", account_id.as_bytes())?;
        storage.set_metadata("device_id", device_id.as_bytes())?;
        storage.set_metadata("salt", &salt)?;

        storage.set_keyring_slot("account_root", ar.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("vault_key", vk.expose_bytes(), &lsk)?;
        storage.set_keyring_slot("ed_seed", &device_ed_seed, &lsk)?;
        storage.set_keyring_slot("pq_seed", &device_pq_seed, &lsk)?;

        let mut vault = Self {
            storage,
            account_id,
            device_id,
            account_root: ar,
            vault_key: vk,
            previous_vault_keys: Vec::new(),
            signing_keys: device_keys,
            lsk,
            lanes: LaneRegistry::new(),
            search_index: SearchIndex::new(),
            last_hlc: None,
        };

        vault.rebuild_state()?;
        Ok(vault)
    }

    /// Revokes a device under this account by authoring a `DeviceRevoke` (kind 4) op.
    ///
    /// # Errors
    /// Returns `TnError` if op generation or storage fails.
    pub fn revoke_device(
        &mut self,
        target_device_id: Id32,
        reason: Option<String>,
    ) -> Result<Id32, TnError> {
        let now_ms = Hlc::current_physical_ms();
        let payload = DeviceRevokePayload {
            v: 1,
            account_id: self.account_id,
            target_device_id,
            revoked_at: now_ms,
            reason,
        };
        let payload_bytes = cbor::encode_canonical(&payload)?;

        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let ct_hash = compute_ct_hash(&payload_bytes);
        let mut obj_bytes = [0u8; 16];
        obj_bytes.copy_from_slice(&target_device_id.as_bytes()[..16]);
        let object_id = Id16::from_bytes(obj_bytes);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::DeviceRevoke,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct_hash,
        };

        let op_id = compute_op_id(&header)?;
        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::DeviceRevoke,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct: payload_bytes,
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;
        self.lanes.revoke_device(target_device_id);

        Ok(op_id)
    }

    /// Access to signing keys.
    #[must_use]
    pub fn signing_keys_ref(&self) -> &SigningKeys {
        &self.signing_keys
    }

    /// Returns all stored ops.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn get_all_ops_internal(&self) -> Result<Vec<(Id32, Op)>, TnError> {
        self.storage.get_all_ops()
    }

    /// Ingests an op that has been verified through the sync pipeline.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn ingest_verified_op(&mut self, op: &Op, op_id: Id32) -> Result<(), TnError> {
        if self.storage.has_op(op_id)? {
            return Ok(());
        }

        self.storage.insert_op(op, op_id)?;
        self.lanes.record_op(op, op_id)?;
        self.last_hlc = Some(match self.last_hlc {
            Some(prev) => Hlc::update(&prev, &op.hlc),
            None => op.hlc,
        });

        match op.kind {
            OpKind::Put => {
                let nk = if let Some(wrapped) = &op.nk_wrap {
                    self.unwrap_note_key_any(op.object_id, wrapped)?
                } else {
                    let (key, _, _) = self.get_note_internal(op.object_id)?;
                    key
                };

                let aad = compute_op_aad(
                    op.v,
                    op.account_id,
                    op.device_id,
                    op.lane_seq,
                    op.object_id,
                    op.kind,
                )?;
                let mut full_ct = Vec::with_capacity(24 + op.ct.len());
                full_ct.extend_from_slice(&op.nonce);
                full_ct.extend_from_slice(&op.ct);

                let pt = open_note_payload(&nk, &aad, &full_ct)?;
                let payload: Payload = cbor::decode_canonical(&pt).or_else(|_| {
                    serde_json::from_slice(&pt)
                        .map_err(|e| TnError::Internal(format!("Decode payload error: {e}")))
                })?;

                self.storage.save_materialized_note(
                    op.object_id,
                    op_id,
                    "active",
                    &payload,
                    &self.lsk,
                )?;
                self.search_index.index_note(
                    op.object_id,
                    &payload.title,
                    &payload.body_md,
                    &payload.tags,
                );
            }
            OpKind::Delete => {
                self.search_index.remove_note(op.object_id);
            }
            OpKind::DeviceRevoke => {
                if let Ok(payload) = cbor::decode_canonical::<DeviceRevokePayload>(&op.ct) {
                    self.lanes.revoke_device(payload.target_device_id);
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Creates a signed `DeviceGossip` message asserting local observed head and checkpoint (SPEC §5, Claim C4).
    ///
    /// # Errors
    /// Returns `TnError` if signing fails.
    pub fn create_gossip(
        &self,
        checkpoint_size: u64,
        checkpoint_root: [u8; 32],
    ) -> Result<DeviceGossip, TnError> {
        let tree_size = self
            .storage
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

        let root_hash = self
            .storage
            .get_metadata("last_verified_account_root")?
            .and_then(|b| {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);

        let now_ms = Hlc::current_physical_ms();

        DeviceGossip::sign(
            self.account_id,
            self.device_id,
            tree_size,
            root_hash,
            checkpoint_size,
            checkpoint_root,
            now_ms,
            &self.signing_keys,
        )
    }

    /// Verifies peer device gossip message against local state to detect split-view attacks (Scenario S7, Claim C4).
    ///
    /// # Errors
    /// Returns `TnError::SplitView` if peer observed a divergent root at the same tree size.
    pub fn verify_gossip(
        &self,
        gossip: &DeviceGossip,
        peer_vk: &VerifyingKeys,
    ) -> Result<(), TnError> {
        gossip.verify(peer_vk)?;

        if gossip.account_id != self.account_id {
            return Err(TnError::Internal("Gossip account mismatch".into()));
        }

        let local_tree_size = self
            .storage
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

        let local_root = self
            .storage
            .get_metadata("last_verified_account_root")?
            .and_then(|b| {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            });

        if let Some(l_root) = local_root {
            if local_tree_size == gossip.tree_size && l_root != gossip.root_hash {
                // Scenario S7: Server presented different account roots for the exact same size to different devices!
                return Err(TnError::SplitView);
            }
        }

        Ok(())
    }

    /// Retrieves the last recorded evidence bundle bytes (CBOR format), if any misbehavior was detected.
    ///
    /// # Errors
    /// Returns `TnError` if reading metadata fails.
    pub fn get_last_evidence_bundle(&self) -> Result<Option<Vec<u8>>, TnError> {
        self.storage.get_metadata("last_evidence_bundle")
    }

    /// Persists an evidence bundle to local metadata.
    ///
    /// # Errors
    /// Returns `TnError` if writing metadata fails.
    pub fn set_last_evidence_bundle(&self, bundle_cbor: &[u8]) -> Result<(), TnError> {
        self.storage
            .set_metadata("last_evidence_bundle", bundle_cbor)
    }

    /// Rotates the Account Root and identity keys (`OpKind::KeyRotate = 5`, ADR-0002 Mitigation 3).
    ///
    /// Generates a fresh 24-word recovery phrase, derives new AR/AIK/VK,
    /// authors a dual cross-signed transition op, updates local keyring slots,
    /// and returns the signed `Op`, its `op_id`, and new 24-word recovery phrase.
    ///
    /// # Errors
    /// Returns `TnError` if entropy generation, signing, or storage update fails.
    pub fn rotate_account_key(&mut self, now_ms: u64) -> Result<(Op, Id32, String), TnError> {
        let old_aik_ed_seed = derive_aik_ed_seed(&self.account_root);
        let old_aik_pq_seed = derive_aik_pq_seed(&self.account_root);
        let old_aik_keys = SigningKeys::from_seeds(&old_aik_ed_seed, &old_aik_pq_seed);

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| TnError::Internal(format!("Entropy generation failed: {e}")))?;
        let new_rk = RecoveryKey::from_bytes(entropy);
        let phrase = encode_recovery_key(&new_rk);

        let new_ar = derive_account_root(&new_rk);
        let new_vk = derive_vault_key(&new_ar);

        let new_aik_ed_seed = derive_aik_ed_seed(&new_ar);
        let new_aik_pq_seed = derive_aik_pq_seed(&new_ar);
        let new_aik_keys = SigningKeys::from_seeds(&new_aik_ed_seed, &new_aik_pq_seed);

        let payload =
            KeyRotatePayload::create(self.account_id, &new_aik_keys, &old_aik_keys, now_ms)?;
        let payload_cbor = payload.to_cbor()?;

        // Author KeyRotate op
        let lane_seq = self.lanes.next_seq(&self.device_id);
        let lane_prev = self.lanes.get_tip(&self.device_id);
        let hlc = Hlc::now(self.last_hlc.as_ref());
        self.last_hlc = Some(hlc);

        let object_id = Id16::from_bytes([0u8; 16]);
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| TnError::Internal(format!("Nonce generation failed: {e}")))?;

        let ct_hash = compute_ct_hash(&payload_cbor);

        let header = OpHeader {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::KeyRotate,
            object_id,
            nk_wrap: None,
            nonce,
            deps: vec![],
            ct_hash,
        };
        let op_id = compute_op_id(&header)?;

        let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
        sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
        sig_msg.extend_from_slice(op_id.as_bytes());
        let hybrid_sig = self.signing_keys.sign(&sig_msg);

        let op = Op {
            v: 1,
            account_id: self.account_id,
            device_id: self.device_id,
            lane_seq,
            lane_prev,
            hlc,
            kind: OpKind::KeyRotate,
            object_id,
            nk_wrap: None,
            nonce,
            deps: vec![],
            ct: payload_cbor,
            sig_ed: hybrid_sig.ed25519,
            sig_pq: hybrid_sig.ml_dsa,
        };

        self.storage.insert_op(&op, op_id)?;
        self.lanes.record_op(&op, op_id)?;

        // Archive current vault key for historical op unwraps (ADR-0002)
        let slot_name = format!("vault_key_archived_{}", self.previous_vault_keys.len());
        self.storage
            .set_keyring_slot(&slot_name, self.vault_key.expose_bytes(), &self.lsk)?;
        self.previous_vault_keys.push(self.vault_key.clone());

        // Update local vault state and persistent slots
        self.account_root = new_ar;
        self.vault_key = new_vk;

        self.storage.set_keyring_slot(
            "account_root",
            self.account_root.expose_bytes(),
            &self.lsk,
        )?;
        self.storage
            .set_keyring_slot("vault_key", self.vault_key.expose_bytes(), &self.lsk)?;

        Ok((op, op_id, phrase))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_create_new_and_crud() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");

        let (mut vault, phrase) = Vault::create_new(&db_path, Some("vault-pass-123")).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        // Create a new note
        let obj_id = vault
            .new_note(
                "My Secret Note",
                "Top secret contents",
                vec!["confidential".into()],
                None,
            )
            .unwrap();

        // List notes
        let list = vault.list_notes(false).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "My Secret Note");

        // Search notes
        let search_res = vault.search("secret").unwrap();
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].object_id, obj_id);

        // Get full note detail
        let detail = vault.get_note(obj_id).unwrap();
        assert_eq!(detail.body_md, "Top secret contents");

        // Verify local
        let report = vault.verify_local().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_ops, 1);
    }
}
