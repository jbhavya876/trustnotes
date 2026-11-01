#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Server relational database layer adhering strictly to `docs/METADATA.md`.
//!
//! Claim C2 enforcement:
//! - Only tables and columns registered in `docs/METADATA.md` are created.
//! - All note content, titles, tags, and keys are strictly absent from the database.
//! - Quantized hourly creation buckets and coarse ciphertext length buckets are enforced.

use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::path::Path;
use tn_types::TnError;

/// Relational storage manager for the untrusted sync server.
pub struct ServerDb {
    conn: Connection,
}

impl ServerDb {
    /// Opens or creates database at specified path.
    pub fn open(path: &Path) -> Result<Self, TnError> {
        let conn = Connection::open(path)
            .map_err(|e| TnError::Internal(format!("Failed to open server db: {e}")))?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Creates in-memory database for testing.
    pub fn in_memory() -> Result<Self, TnError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| TnError::Internal(format!("Failed to open in-memory db: {e}")))?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Initializes tables strictly matching `docs/METADATA.md §2`.
    fn init_schema(&self) -> Result<(), TnError> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;

                 -- Table 2.1: accounts
                 CREATE TABLE IF NOT EXISTS accounts (
                     account_id BLOB PRIMARY KEY,
                     aik_pub_bundle BLOB NOT NULL,
                     created_bucket INTEGER NOT NULL
                 );

                 -- Table 2.2: devices
                 CREATE TABLE IF NOT EXISTS devices (
                     device_id BLOB PRIMARY KEY,
                     account_id BLOB NOT NULL,
                     cert BLOB NOT NULL,
                     revoked_at_index INTEGER,
                     FOREIGN KEY(account_id) REFERENCES accounts(account_id)
                 );

                 -- Table 2.3: ops
                 CREATE TABLE IF NOT EXISTS ops (
                     account_id BLOB NOT NULL,
                     idx INTEGER NOT NULL,
                     op_id BLOB NOT NULL,
                     device_id BLOB NOT NULL,
                     ct_hash BLOB NOT NULL,
                     ct_len_bucket INTEGER NOT NULL,
                     op_bytes BLOB NOT NULL,
                     received_epoch INTEGER NOT NULL,
                     PRIMARY KEY(account_id, idx)
                 );
                 CREATE INDEX IF NOT EXISTS idx_ops_account_device ON ops (account_id, device_id);

                 -- Table 2.4: account_heads
                 CREATE TABLE IF NOT EXISTS account_heads (
                     account_id BLOB PRIMARY KEY,
                     size INTEGER NOT NULL,
                     root BLOB NOT NULL,
                     updated_epoch INTEGER NOT NULL
                 );

                 -- Table 2.5: epochs
                 CREATE TABLE IF NOT EXISTS epochs (
                     epoch_num INTEGER PRIMARY KEY,
                     root BLOB NOT NULL,
                     published_at INTEGER NOT NULL
                 );

                 -- Table 2.6: receipts_issued
                 CREATE TABLE IF NOT EXISTS receipts_issued (
                     account_id BLOB NOT NULL,
                     op_id BLOB PRIMARY KEY,
                     mmd_epoch INTEGER NOT NULL
                 );

                 -- Table 2.7: nonces
                 CREATE TABLE IF NOT EXISTS nonces (
                     device_id BLOB NOT NULL,
                     nonce BLOB NOT NULL,
                     expires_at INTEGER NOT NULL,
                     PRIMARY KEY(device_id, nonce)
                 );

                 -- Table 2.8: invites
                 CREATE TABLE IF NOT EXISTS invites (
                     token_hash BLOB PRIMARY KEY,
                     used_at INTEGER
                 );",
            )
            .map_err(|e| TnError::Internal(format!("Init server schema failed: {e}")))
    }

    /// Access to internal connection for operations.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Checks and consumes an anti-replay nonce.
    /// Returns `Err(TnError::OrderViolation)` if the nonce was already used and not expired.
    pub fn check_and_record_nonce(
        &self,
        device_id: &[u8; 32],
        nonce: &[u8; 16],
        expires_at: u64,
        now: u64,
    ) -> Result<(), TnError> {
        // Clean expired nonces first
        let _ = self.conn.execute(
            "DELETE FROM nonces WHERE expires_at < ?1",
            params![now as i64],
        );

        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM nonces WHERE device_id = ?1 AND nonce = ?2")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let exists = stmt
            .exists(params![device_id.as_slice(), nonce.as_slice()])
            .map_err(|e| TnError::Internal(e.to_string()))?;

        if exists {
            return Err(TnError::OrderViolation);
        }

        self.conn
            .execute(
                "INSERT INTO nonces (device_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
                params![device_id.as_slice(), nonce.as_slice(), expires_at as i64],
            )
            .map_err(|e| TnError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Registers a new account.
    pub fn insert_account(
        &self,
        account_id: &[u8; 32],
        aik_bundle: &[u8],
        created_bucket: u64,
    ) -> Result<(), TnError> {
        self.conn
            .execute(
                "INSERT INTO accounts (account_id, aik_pub_bundle, created_bucket) VALUES (?1, ?2, ?3)",
                params![account_id.as_slice(), aik_bundle, created_bucket as i64],
            )
            .map_err(|e| TnError::Internal(format!("Insert account error: {e}")))?;
        Ok(())
    }

    /// Enrolls a device under an account.
    pub fn insert_device(
        &self,
        device_id: &[u8; 32],
        account_id: &[u8; 32],
        cert: &[u8],
    ) -> Result<(), TnError> {
        self.conn
            .execute(
                "INSERT INTO devices (device_id, account_id, cert, revoked_at_index) VALUES (?1, ?2, ?3, NULL)",
                params![device_id.as_slice(), account_id.as_slice(), cert],
            )
            .map_err(|e| TnError::Internal(format!("Insert device error: {e}")))?;
        Ok(())
    }

    /// Checks if a device is active (not revoked).
    pub fn is_device_active(&self, device_id: &[u8; 32]) -> Result<bool, TnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT revoked_at_index FROM devices WHERE device_id = ?1")
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let mut rows = stmt
            .query(params![device_id.as_slice()])
            .map_err(|e| TnError::Internal(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| TnError::Internal(e.to_string()))? {
            let revoked: Option<i64> = row.get(0).map_err(|e| TnError::Internal(e.to_string()))?;
            Ok(revoked.is_none())
        } else {
            Ok(false)
        }
    }

    /// Revokes a device by setting its revoked_at_index.
    pub fn revoke_device(
        &self,
        device_id: &[u8; 32],
        revoked_at_index: i64,
    ) -> Result<(), TnError> {
        self.conn
            .execute(
                "UPDATE devices SET revoked_at_index = ?1 WHERE device_id = ?2",
                params![revoked_at_index, device_id.as_slice()],
            )
            .map_err(|e| TnError::Internal(format!("Revoke device error: {e}")))?;
        Ok(())
    }

    /// Verifies schema conformity against `docs/METADATA.md` allowlist.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if any column or table in SQLite is NOT registered in `METADATA.md`.
    pub fn verify_schema_conformity(&self) -> Result<(), TnError> {
        // Allowed tables and columns from METADATA.md §2
        let allowlist: [(&str, &[&str]); 8] = [
            (
                "accounts",
                &["account_id", "aik_pub_bundle", "created_bucket"],
            ),
            (
                "devices",
                &["device_id", "account_id", "cert", "revoked_at_index"],
            ),
            (
                "ops",
                &[
                    "account_id",
                    "idx",
                    "op_id",
                    "device_id",
                    "ct_hash",
                    "ct_len_bucket",
                    "op_bytes",
                    "received_epoch",
                ],
            ),
            (
                "account_heads",
                &["account_id", "size", "root", "updated_epoch"],
            ),
            ("epochs", &["epoch_num", "root", "published_at"]),
            ("receipts_issued", &["account_id", "op_id", "mmd_epoch"]),
            ("nonces", &["device_id", "nonce", "expires_at"]),
            ("invites", &["token_hash", "used_at"]),
        ];

        let allowed_tables: HashSet<&str> = allowlist.iter().map(|(t, _)| *t).collect();

        // Query SQLite master for user tables
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .map_err(|e| TnError::Internal(e.to_string()))?;

        let table_names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| TnError::Internal(e.to_string()))?
            .collect::<Result<_, _>>()
            .map_err(|e| TnError::Internal(e.to_string()))?;

        for table in &table_names {
            if !allowed_tables.contains(table.as_str()) {
                return Err(TnError::Internal(format!(
                    "Unregistered table '{table}' violates Claim C2 / METADATA.md!"
                )));
            }

            let expected_cols: HashSet<&str> = allowlist
                .iter()
                .find(|(t, _)| *t == table.as_str())
                .unwrap()
                .1
                .iter()
                .copied()
                .collect();

            let mut col_stmt = self
                .conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(|e| TnError::Internal(e.to_string()))?;

            let cols: Vec<String> = col_stmt
                .query_map([], |row| row.get(1))
                .map_err(|e| TnError::Internal(e.to_string()))?
                .collect::<Result<_, _>>()
                .map_err(|e| TnError::Internal(e.to_string()))?;

            for col in &cols {
                if !expected_cols.contains(col.as_str()) {
                    return Err(TnError::Internal(format!(
                        "Unregistered column '{table}.{col}' violates Claim C2 / METADATA.md!"
                    )));
                }
            }
        }

        Ok(())
    }
}
