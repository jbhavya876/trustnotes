#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! SQLite storage engine with per-column AEAD under LocalStorageKey.
//!
//! Guarantees:
//! - All sensitive fields (title, body, tags, keyring slots) are stored encrypted.
//! - Local canary strings never appear in plaintext inside SQLite files on disk.

use rusqlite::{params, Connection};
use std::path::Path;
use tn_crypto::{open_local, seal_local, LocalStorageKey};
use tn_oplog::{Op, Payload};
use tn_types::{Id16, Id32, TnError};

/// SQLite storage manager for TrustNotes vault.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Opens or creates SQLite database at given path with WAL mode.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if connection or schema creation fails.
    pub fn open(path: &Path) -> Result<Self, TnError> {
        let conn = Connection::open(path)
            .map_err(|e| TnError::Internal(format!("Failed to open SQLite db: {e}")))?;

        // Performance and durability pragmas
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| TnError::Internal(format!("Failed to set pragmas: {e}")))?;

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates in-memory storage for testing.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on failure.
    pub fn in_memory() -> Result<Self, TnError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| TnError::Internal(format!("Failed to open in-memory db: {e}")))?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), TnError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS keyring (
                    slot TEXT PRIMARY KEY,
                    ct BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ops (
                    op_id BLOB PRIMARY KEY,
                    account_id BLOB NOT NULL,
                    device_id BLOB NOT NULL,
                    lane_seq INTEGER NOT NULL,
                    lane_prev BLOB,
                    kind INTEGER NOT NULL,
                    object_id BLOB NOT NULL,
                    hlc_wall INTEGER NOT NULL,
                    hlc_counter INTEGER NOT NULL,
                    raw_cbor BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ops_lane ON ops (device_id, lane_seq);
                CREATE INDEX IF NOT EXISTS idx_ops_object ON ops (object_id);

                CREATE TABLE IF NOT EXISTS notes_materialized (
                    object_id BLOB PRIMARY KEY,
                    head_op_id BLOB NOT NULL,
                    status TEXT NOT NULL,
                    title_ct BLOB NOT NULL,
                    body_ct BLOB NOT NULL,
                    tags_ct BLOB NOT NULL,
                    notebook_id BLOB,
                    flags INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );",
            )
            .map_err(|e| TnError::Internal(format!("Failed to initialize schema: {e}")))
    }

    /// Stores a metadata value.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on DB failure.
    pub fn set_metadata(&self, key: &str, val: &[u8]) -> Result<(), TnError> {
        self.conn
            .execute(
                "INSERT INTO metadata (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, val],
            )
            .map_err(|e| TnError::Internal(format!("Set metadata error: {e}")))?;
        Ok(())
    }

    /// Gets a metadata value.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on DB failure.
    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM metadata WHERE key = ?1")
            .map_err(|e| TnError::Internal(format!("Prepare get_metadata: {e}")))?;

        let mut rows = stmt
            .query(params![key])
            .map_err(|e| TnError::Internal(format!("Query get_metadata: {e}")))?;

        if let Some(row) = rows.next().map_err(|e| TnError::Internal(e.to_string()))? {
            let val: Vec<u8> = row.get(0).map_err(|e| TnError::Internal(e.to_string()))?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Stores encrypted keyring slot.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on failure.
    pub fn set_keyring_slot(
        &self,
        slot: &str,
        data: &[u8],
        lsk: &LocalStorageKey,
    ) -> Result<(), TnError> {
        let ct = seal_local(lsk, slot.as_bytes(), data)?;
        self.conn
            .execute(
                "INSERT INTO keyring (slot, ct) VALUES (?1, ?2)
                 ON CONFLICT(slot) DO UPDATE SET ct = excluded.ct",
                params![slot, ct],
            )
            .map_err(|e| TnError::Internal(format!("Set keyring slot error: {e}")))?;
        Ok(())
    }

    /// Reads and decrypts keyring slot.
    ///
    /// # Errors
    /// Returns `TnError` if slot is missing, DB fails, or decryption fails.
    pub fn get_keyring_slot(
        &self,
        slot: &str,
        lsk: &LocalStorageKey,
    ) -> Result<Option<Vec<u8>>, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ct FROM keyring WHERE slot = ?1")
            .map_err(|e| TnError::Internal(format!("Prepare get_keyring_slot: {e}")))?;

        let mut rows = stmt
            .query(params![slot])
            .map_err(|e| TnError::Internal(format!("Query get_keyring_slot: {e}")))?;

        if let Some(row) = rows.next().map_err(|e| TnError::Internal(e.to_string()))? {
            let ct: Vec<u8> = row.get(0).map_err(|e| TnError::Internal(e.to_string()))?;
            let pt = open_local(lsk, slot.as_bytes(), &ct)?;
            Ok(Some(pt))
        } else {
            Ok(None)
        }
    }

    /// Inserts raw operation into the ops table.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on SQL error.
    pub fn insert_op(&self, op: &Op, op_id: Id32) -> Result<(), TnError> {
        let raw_cbor = op.to_cbor()?;
        let lane_prev_bytes = op.lane_prev.map(|p| p.as_bytes().to_vec());

        self.conn
            .execute(
                "INSERT OR IGNORE INTO ops (op_id, account_id, device_id, lane_seq, lane_prev, kind, object_id, hlc_wall, hlc_counter, raw_cbor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    op_id.as_bytes().as_slice(),
                    op.account_id.as_bytes().as_slice(),
                    op.device_id.as_bytes().as_slice(),
                    op.lane_seq as i64,
                    lane_prev_bytes,
                    op.kind as u8,
                    op.object_id.as_bytes().as_slice(),
                    op.hlc.wall_ms as i64,
                    op.hlc.counter as i64,
                    raw_cbor,
                ],
            )
            .map_err(|e| TnError::Internal(format!("Insert op failed: {e}")))?;
        Ok(())
    }

    /// Checks if an operation already exists in storage.
    ///
    /// # Errors
    /// Returns `TnError::Internal` on SQL error.
    pub fn has_op(&self, op_id: Id32) -> Result<bool, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM ops WHERE op_id = ?1")
            .map_err(|e| TnError::Internal(e.to_string()))?;
        let exists = stmt
            .exists(params![op_id.as_bytes().as_slice()])
            .map_err(|e| TnError::Internal(e.to_string()))?;
        Ok(exists)
    }

    /// Reads all stored ops in total order.
    ///
    /// # Errors
    /// Returns `TnError` if reading or decoding fails.
    pub fn get_all_ops(&self) -> Result<Vec<(Id32, Op)>, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_id, raw_cbor FROM ops ORDER BY rowid ASC")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let cbor: Vec<u8> = row.get(1)?;
                Ok((id_bytes, cbor))
            })
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let mut out = Vec::new();
        for item in rows {
            let (id_bytes, cbor) = item.map_err(|e| TnError::Internal(e.to_string()))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let op = Op::from_cbor(&cbor)?;
            out.push((Id32::from_bytes(arr), op));
        }
        Ok(out)
    }

    /// Reads all ops for a specific object.
    ///
    /// # Errors
    /// Returns `TnError` on failure.
    pub fn get_ops_for_object(&self, object_id: Id16) -> Result<Vec<(Id32, Op)>, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_id, raw_cbor FROM ops WHERE object_id = ?1 ORDER BY hlc_wall ASC, hlc_counter ASC")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let rows = stmt
            .query_map(params![object_id.as_bytes().as_slice()], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let cbor: Vec<u8> = row.get(1)?;
                Ok((id_bytes, cbor))
            })
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let mut out = Vec::new();
        for item in rows {
            let (id_bytes, cbor) = item.map_err(|e| TnError::Internal(e.to_string()))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let op = Op::from_cbor(&cbor)?;
            out.push((Id32::from_bytes(arr), op));
        }
        Ok(out)
    }

    /// Updates or inserts a note into the materialized table with LSK AEAD encryption.
    ///
    /// # Errors
    /// Returns `TnError` on encryption or DB failure.
    pub fn save_materialized_note(
        &self,
        object_id: Id16,
        head_op_id: Id32,
        status: &str,
        payload: &Payload,
        lsk: &LocalStorageKey,
    ) -> Result<(), TnError> {
        let title_ct = seal_local(lsk, b"title", payload.title.as_bytes())?;
        let body_ct = seal_local(lsk, b"body", payload.body_md.as_bytes())?;
        let tags_json = serde_json::to_vec(&payload.tags)
            .map_err(|e| TnError::Internal(format!("Tags serialization error: {e}")))?;
        let tags_ct = seal_local(lsk, b"tags", &tags_json)?;

        let notebook_bytes = payload.notebook_id.map(|n| n.as_bytes().to_vec());

        self.conn
            .execute(
                "INSERT INTO notes_materialized (object_id, head_op_id, status, title_ct, body_ct, tags_ct, notebook_id, flags, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(object_id) DO UPDATE SET
                    head_op_id = excluded.head_op_id,
                    status = excluded.status,
                    title_ct = excluded.title_ct,
                    body_ct = excluded.body_ct,
                    tags_ct = excluded.tags_ct,
                    notebook_id = excluded.notebook_id,
                    flags = excluded.flags,
                    updated_at = excluded.updated_at",
                params![
                    object_id.as_bytes().as_slice(),
                    head_op_id.as_bytes().as_slice(),
                    status,
                    title_ct,
                    body_ct,
                    tags_ct,
                    notebook_bytes,
                    payload.flags as i64,
                    payload.created_at as i64,
                    payload.updated_at as i64,
                ],
            )
            .map_err(|e| TnError::Internal(format!("Save materialized note error: {e}")))?;

        Ok(())
    }

    /// Reads all notes from materialized table and decrypts them.
    ///
    /// # Errors
    /// Returns `TnError` on DB or decryption error.
    pub fn list_materialized_notes(
        &self,
        lsk: &LocalStorageKey,
    ) -> Result<Vec<(Id16, Id32, String, Payload)>, TnError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT object_id, head_op_id, status, title_ct, body_ct, tags_ct, notebook_id, flags, created_at, updated_at
                 FROM notes_materialized
                 ORDER BY updated_at DESC",
            )
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let obj_bytes: Vec<u8> = row.get(0)?;
                let head_bytes: Vec<u8> = row.get(1)?;
                let status: String = row.get(2)?;
                let title_ct: Vec<u8> = row.get(3)?;
                let body_ct: Vec<u8> = row.get(4)?;
                let tags_ct: Vec<u8> = row.get(5)?;
                let notebook_bytes: Option<Vec<u8>> = row.get(6)?;
                let flags: i64 = row.get(7)?;
                let created_at: i64 = row.get(8)?;
                let updated_at: i64 = row.get(9)?;

                Ok((
                    obj_bytes,
                    head_bytes,
                    status,
                    title_ct,
                    body_ct,
                    tags_ct,
                    notebook_bytes,
                    flags as u32,
                    created_at as u64,
                    updated_at as u64,
                ))
            })
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let mut out = Vec::new();
        for item in rows {
            let (
                obj_bytes,
                head_bytes,
                status,
                title_ct,
                body_ct,
                tags_ct,
                notebook_bytes,
                flags,
                created_at,
                updated_at,
            ) = item.map_err(|e| TnError::Internal(e.to_string()))?;

            let mut obj_arr = [0u8; 16];
            obj_arr.copy_from_slice(&obj_bytes);
            let mut head_arr = [0u8; 32];
            head_arr.copy_from_slice(&head_bytes);

            let title_bytes = open_local(lsk, b"title", &title_ct)?;
            let title = String::from_utf8(title_bytes)
                .map_err(|e| TnError::Internal(format!("Invalid UTF-8 title: {e}")))?;

            let body_bytes = open_local(lsk, b"body", &body_ct)?;
            let body_md = String::from_utf8(body_bytes)
                .map_err(|e| TnError::Internal(format!("Invalid UTF-8 body: {e}")))?;

            let tags_bytes = open_local(lsk, b"tags", &tags_ct)?;
            let tags: Vec<String> = serde_json::from_slice(&tags_bytes)
                .map_err(|e| TnError::Internal(format!("Failed to parse tags: {e}")))?;

            let notebook_id = notebook_bytes.map(|b| {
                let mut n_arr = [0u8; 16];
                n_arr.copy_from_slice(&b);
                Id16::from_bytes(n_arr)
            });

            let payload = Payload {
                schema_v: 1,
                title,
                body_md,
                tags,
                notebook_id,
                flags,
                created_at,
                updated_at,
                attachments: Vec::new(),
            };

            out.push((
                Id16::from_bytes(obj_arr),
                Id32::from_bytes(head_arr),
                status,
                payload,
            ));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_keyring_and_ops() {
        let storage = Storage::in_memory().unwrap();
        let lsk = LocalStorageKey::from_bytes([0x42; 32]);

        // Keyring roundtrip
        storage
            .set_keyring_slot("account_root", b"secret-root", &lsk)
            .unwrap();
        let retrieved = storage
            .get_keyring_slot("account_root", &lsk)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved, b"secret-root");

        // Materialized note save and retrieve
        let obj_id = Id16::from_bytes([1u8; 16]);
        let head_id = Id32::from_bytes([2u8; 32]);
        let payload = Payload {
            schema_v: 1,
            title: "Confidential Note".into(),
            body_md: "Encrypted content".into(),
            tags: vec!["secret".into()],
            notebook_id: None,
            flags: 0,
            created_at: 100,
            updated_at: 200,
            attachments: Vec::new(),
        };

        storage
            .save_materialized_note(obj_id, head_id, "active", &payload, &lsk)
            .unwrap();
        let notes = storage.list_materialized_notes(&lsk).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].3.title, "Confidential Note");
    }
}
