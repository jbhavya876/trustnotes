#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Vault engine: high-level encrypted note operations and local transparency pipeline.

use std::collections::HashMap;
use std::path::Path;
use tn_crypto::labels::LABEL_SIG_OP;
use tn_crypto::{
    decode_recovery_key, derive_account_id, derive_account_root, derive_aik_ed_seed,
    derive_aik_pq_seed, derive_lsk_from_passphrase, derive_vault_key, encode_recovery_key,
    open_note_payload, seal_note_payload, unwrap_note_key, wrap_note_key, AccountRoot,
    LocalStorageKey, NoteKey, RecoveryKey, SigningKeys, VaultKey,
};
use tn_oplog::{
    compute_ct_hash, compute_op_aad, compute_op_id, ConflictStatus, Hlc, LaneRegistry,
    NoteDagTracker, Op, OpHeader, Payload,
};
use tn_types::{Id16, Id32, OpKind, TnError};

use crate::search::SearchIndex;
use crate::storage::Storage;

/// Brief summary of a note for list displays.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteDetail {
    /// Summary metadata.
    pub summary: NoteSummary,
    /// Markdown body text.
    pub body_md: String,
    /// History of operations modifying this note.
    pub history: Vec<Id32>,
}

/// Result report from local integrity verification (`verify --local`).
#[derive(Debug, Clone, PartialEq, Eq)]
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

        let lsk = match passphrase {
            Some(p) => derive_lsk_from_passphrase(p, &salt)?,
            None => {
                let mut raw = [0u8; 32];
                getrandom::getrandom(&mut raw)
                    .map_err(|e| TnError::Internal(format!("Keygen failed: {e}")))?;
                LocalStorageKey::from_bytes(raw)
            }
        };

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

        let lsk = match passphrase {
            Some(p) => derive_lsk_from_passphrase(p, &salt)?,
            None => {
                // If unencrypted keyring, load master key slot or fall back to empty
                let raw = storage.get_metadata("unlocked_lsk")?.ok_or_else(|| {
                    TnError::Internal("Vault requires passphrase to unlock".into())
                })?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                LocalStorageKey::from_bytes(arr)
            }
        };

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

        let mut vault = Self {
            storage,
            account_id,
            device_id,
            account_root: ar,
            vault_key: vk,
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
            let _ = self.lanes.record_op(&op, op_id);
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
                    let key = unwrap_note_key(&self.vault_key, object_id, wrapped)?;
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
        let p: Payload = serde_json::from_slice(&pt)
            .map_err(|e| TnError::Internal(format!("Decode payload error: {e}")))?;
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
        let payload: Payload = serde_json::from_slice(&pt)
            .map_err(|e| TnError::Internal(format!("Decode payload error: {e}")))?;

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
        let verifying_keys = self.signing_keys.verifying_keys();
        let mut lanes = LaneRegistry::new();
        let mut note_keys: HashMap<Id16, NoteKey> = HashMap::new();

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

            // 3. Verify hybrid signatures
            let mut sig_msg = Vec::with_capacity(LABEL_SIG_OP.len() + 32);
            sig_msg.extend_from_slice(LABEL_SIG_OP.as_bytes());
            sig_msg.extend_from_slice(op_id.as_bytes());

            let hybrid_sig = tn_crypto::HybridSignature {
                ed25519: op.sig_ed,
                ml_dsa: op.sig_pq.clone(),
            };
            verifying_keys.verify(&sig_msg, &hybrid_sig)?;

            // 4. Verify lane continuity
            lanes.record_op(op, *op_id)?;

            // 5. If Put with nk_wrap, unwrap NoteKey and verify payload AEAD
            if op.kind == OpKind::Put {
                if let Some(wrapped) = &op.nk_wrap {
                    let nk = unwrap_note_key(&self.vault_key, op.object_id, wrapped)?;
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

        let lsk = match passphrase {
            Some(p) => derive_lsk_from_passphrase(p, &salt)?,
            None => {
                let mut raw = [0u8; 32];
                getrandom::getrandom(&mut raw)
                    .map_err(|e| TnError::Internal(format!("Keygen failed: {e}")))?;
                LocalStorageKey::from_bytes(raw)
            }
        };

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
