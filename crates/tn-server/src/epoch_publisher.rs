#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Epoch Publisher: builds privacy-preserving epoch trees and global transparency log checkpoints.
//!
//! Enforces:
//! - Hashed account leaves using `tn/v1/epoch-leaf` to prevent monitor account enumeration.
//! - Global append-only log of epoch roots.
//! - Server-signed Checkpoint production with witness cosignatures.

use rusqlite::params;
use std::collections::HashMap;
use tn_crypto::SigningKeys;
use tn_merkle::MerkleTree;
use tn_tlog::{epoch_leaf_hash, Checkpoint, Cosignature};
use tn_types::TnError;

use crate::db::ServerDb;

/// Coordinates epoch publications and global transparency log commitments.
pub struct EpochPublisher {
    server_keys: SigningKeys,
    global_log: MerkleTree,
    epoch_trees: HashMap<u64, MerkleTree>,
    origin: String,
}

impl EpochPublisher {
    /// Creates a new EpochPublisher.
    #[must_use]
    pub fn new(server_keys: SigningKeys, origin: String) -> Self {
        Self {
            server_keys,
            global_log: MerkleTree::new(),
            epoch_trees: HashMap::new(),
            origin,
        }
    }

    /// Publishes an epoch commitment across all accounts updated in `epoch_num`.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on DB or cryptographic failure.
    pub fn publish_epoch(
        &mut self,
        db: &ServerDb,
        epoch_num: u64,
        now_ms: u64,
    ) -> Result<Checkpoint, TnError> {
        // 1. Fetch updated accounts for this epoch
        let mut stmt = db
            .conn()
            .prepare("SELECT account_id, size, root FROM account_heads WHERE updated_epoch = ?1")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let rows = stmt
            .query_map(params![epoch_num as i64], |row| {
                let acc: Vec<u8> = row.get(0)?;
                let size: i64 = row.get(1)?;
                let root: Vec<u8> = row.get(2)?;
                Ok((acc, size as u64, root))
            })
            .map_err(|e| TnError::Internal(e.to_string()))?;

        // 2. Build epoch tree with privacy-preserving leaves
        let mut epoch_tree = MerkleTree::new();

        for item in rows {
            let (acc_bytes, size, root_bytes) =
                item.map_err(|e| TnError::Internal(e.to_string()))?;
            let mut acc = [0u8; 32];
            acc.copy_from_slice(&acc_bytes);
            let mut root = [0u8; 32];
            root.copy_from_slice(&root_bytes);

            let leaf = epoch_leaf_hash(&acc, size, &root);
            epoch_tree.append_leaf_hash(leaf);
        }

        let epoch_root = epoch_tree.root();

        // 3. Persist epoch to DB
        db.conn()
            .execute(
                "INSERT INTO epochs (epoch_num, root, published_at) VALUES (?1, ?2, ?3)",
                params![
                    epoch_num as i64,
                    epoch_root.as_bytes().as_slice(),
                    now_ms as i64
                ],
            )
            .map_err(|e| TnError::Internal(format!("Insert epoch failed: {e}")))?;

        // 4. Append epoch root to global transparency log
        self.global_log.append_leaf_hash(*epoch_root.as_bytes());
        let global_size = self.global_log.size();
        let global_root = self.global_log.root();

        self.epoch_trees.insert(epoch_num, epoch_tree);

        // 5. Create signed checkpoint
        let mut cp = Checkpoint {
            origin: self.origin.clone(),
            size: global_size,
            root_hash: *global_root.as_bytes(),
            timestamp_ms: now_ms,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };

        let body = cp.signed_body();
        cp.server_sig = self.server_keys.sign(&body);

        Ok(cp)
    }

    /// Attaches a witness cosignature to an existing checkpoint.
    pub fn add_cosignature(checkpoint: &mut Checkpoint, cosig: Cosignature) {
        checkpoint.cosignatures.push(cosig);
    }

    /// Returns global log Merkle tree.
    #[must_use]
    pub fn global_log(&self) -> &MerkleTree {
        &self.global_log
    }

    /// Returns epoch tree for a specific epoch.
    #[must_use]
    pub fn get_epoch_tree(&self, epoch_num: u64) -> Option<&MerkleTree> {
        self.epoch_trees.get(&epoch_num)
    }
}
