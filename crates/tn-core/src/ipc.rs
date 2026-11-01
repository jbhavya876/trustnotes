#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Local IPC Daemon for `TrustNotes` (SPEC §9, ADR-0002).
//!
//! Provides a secure local IPC server binding exclusively to loopback (`127.0.0.1`),
//! authenticated with a 256-bit unguessable CSPRNG token to enforce process and
//! user isolation boundaries (mitigates Threat S16: Cross-user local IPC).
//!
//! Framing: 4-byte big-endian length prefix followed by canonical CBOR payload.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tn_oplog::Hlc;
use tn_types::{cbor, Id16, Id32, TnError};

use crate::vault::{NoteDetail, NoteSummary, Vault, VerificationReport};

/// Unguessable 256-bit auth token protecting the IPC daemon interface.
pub type IpcToken = [u8; 32];

/// Generates a fresh unguessable 256-bit authentication token using OS CSPRNG.
///
/// # Errors
/// Returns `TnError::Internal` if entropy generation fails.
pub fn generate_auth_token() -> Result<IpcToken, TnError> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token)
        .map_err(|e| TnError::Internal(format!("Failed to generate auth token: {e}")))?;
    Ok(token)
}

/// Writes auth token to disk with restricted permissions where supported.
///
/// # Errors
/// Returns `TnError::Internal` on I/O error.
pub fn write_token_file(path: &Path, token: &IpcToken) -> Result<(), TnError> {
    let hex_str = hex::encode(token);
    std::fs::write(path, hex_str)
        .map_err(|e| TnError::Internal(format!("Failed to write token file: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Reads hex-encoded auth token from disk.
///
/// # Errors
/// Returns `TnError` if file cannot be read or hex decode fails.
pub fn read_token_file(path: &Path) -> Result<IpcToken, TnError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| TnError::Internal(format!("Failed to read token file: {e}")))?;
    let bytes = hex::decode(text.trim())
        .map_err(|e| TnError::Internal(format!("Invalid hex in token file: {e}")))?;
    if bytes.len() != 32 {
        return Err(TnError::Internal("Token length is not 32 bytes".into()));
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&bytes);
    Ok(token)
}

/// Top-level IPC request sent from client to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// 256-bit authentication token.
    pub token: IpcToken,
    /// Command to execute.
    pub command: IpcCommand,
}

/// High-level commands supported by the TrustNotes local daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcCommand {
    /// Ping daemon for liveness.
    Ping,
    /// Get daemon and vault status.
    Status,
    /// List active or trashed notes.
    ListNotes { include_trashed: bool },
    /// Fetch full detail of a specific note.
    GetNote { object_id: Id16 },
    /// Create a new encrypted note.
    NewNote {
        title: String,
        body_md: String,
        tags: Vec<String>,
        notebook_id: Option<Id16>,
    },
    /// Edit an existing note.
    EditNote {
        object_id: Id16,
        title: String,
        body_md: String,
        tags: Vec<String>,
    },
    /// Move a note to trash.
    DeleteNote { object_id: Id16 },
    /// Permanently shred a note.
    ShredNote { object_id: Id16 },
    /// Search notes via inverted index.
    Search { query: String },
    /// Rotate account master key and issue new recovery phrase (Claim C8, ADR-0002).
    RotateKey,
    /// Run local integrity and Merkle DAG verification.
    VerifyLocal,
    /// Lock the vault, dropping cryptographic keys from memory.
    Lock,
    /// Unlock the vault with passphrase.
    Unlock { passphrase: Option<String> },
    /// Gracefully terminate the daemon process.
    Stop,
}

/// Response returned from daemon to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Command executed successfully with returned payload.
    Ok(IpcPayload),
    /// Command execution failed with descriptive error.
    Err(String),
}

/// Success payload types for IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcPayload {
    /// Liveness pong.
    Pong,
    /// Current daemon status.
    Status(DaemonStatus),
    /// List of note summaries.
    NoteList(Vec<NoteSummary>),
    /// Detail of fetched note.
    Note(NoteDetail),
    /// Identifier of newly created note.
    NoteCreated(Id16),
    /// Identifier of newly committed op modifying note.
    NoteUpdated(Id32),
    /// Confirmation of note deletion/shredding.
    NoteDeleted(Id32),
    /// Result of key rotation containing new op ID and recovery phrase.
    KeyRotated {
        op_id: Id32,
        new_recovery_phrase: String,
    },
    /// Local verification report.
    Verification(VerificationReport),
    /// Vault successfully locked.
    Locked,
    /// Vault successfully unlocked.
    Unlocked,
    /// Daemon stopped.
    Stopped,
}

/// Status summary returned by daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Account identifier (None if locked).
    pub account_id: Option<Id32>,
    /// Device identifier (None if locked).
    pub device_id: Option<Id32>,
    /// Count of active notes.
    pub active_notes_count: usize,
    /// Whether vault is currently locked in memory.
    pub is_locked: bool,
}

/// Writes a length-prefixed canonical CBOR message to an I/O stream.
fn send_cbor<W: Write, T: Serialize>(w: &mut W, val: &T) -> Result<(), TnError> {
    let bytes = cbor::encode_canonical(val)?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| TnError::Internal("Message exceeds max length".into()))?;
    w.write_all(&len.to_be_bytes())
        .map_err(|e| TnError::Internal(format!("IPC write length failed: {e}")))?;
    w.write_all(&bytes)
        .map_err(|e| TnError::Internal(format!("IPC write payload failed: {e}")))?;
    w.flush()
        .map_err(|e| TnError::Internal(format!("IPC flush failed: {e}")))?;
    Ok(())
}

/// Reads a length-prefixed canonical CBOR message from an I/O stream.
fn recv_cbor<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, TnError> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)
        .map_err(|e| TnError::Internal(format!("IPC read length failed: {e}")))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(TnError::Internal("IPC message exceeds 16MB limit".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| TnError::Internal(format!("IPC read payload failed: {e}")))?;
    cbor::decode_canonical(&buf)
}

/// Local IPC Daemon Server managing an in-memory vault and accepting authenticated connections.
pub struct DaemonServer {
    vault: Arc<Mutex<Option<Vault>>>,
    db_path: PathBuf,
    token: IpcToken,
    port: u16,
    shutdown: Arc<AtomicBool>,
}

impl DaemonServer {
    /// Binds and initializes the DaemonServer on loopback `127.0.0.1:<port>`.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if TCP binding fails.
    pub fn bind(
        vault: Option<Vault>,
        db_path: PathBuf,
        token: IpcToken,
        port: u16,
    ) -> Result<(Self, TcpListener), TnError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .map_err(|e| TnError::Internal(format!("Failed to bind loopback TCP: {e}")))?;
        let bound_port = listener
            .local_addr()
            .map_err(|e| TnError::Internal(format!("Failed to get local port: {e}")))?
            .port();

        // Non-blocking mode with timeout so accept can check shutdown periodically
        listener
            .set_nonblocking(false)
            .map_err(|e| TnError::Internal(format!("Failed to set blocking: {e}")))?;

        let server = Self {
            vault: Arc::new(Mutex::new(vault)),
            db_path,
            token,
            port: bound_port,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        Ok((server, listener))
    }

    /// Bound port number.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Shutdown signal controller.
    #[must_use]
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Processes a single client connection.
    pub fn handle_client(&self, mut stream: TcpStream) -> Result<(), TnError> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let req: IpcRequest = match recv_cbor(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                let resp = IpcResponse::Err(format!("Decode request failed: {e}"));
                let _ = send_cbor(&mut stream, &resp);
                return Err(e);
            }
        };

        // Constant-time check / authentication check (Threat S16)
        if subtle_slices_eq(&req.token, &self.token) != 1 {
            let resp = IpcResponse::Err("Unauthorized: invalid IPC authentication token".into());
            let _ = send_cbor(&mut stream, &resp);
            return Err(TnError::Internal("Unauthorized connection rejected".into()));
        }

        // Process authenticated command
        let resp = self.dispatch_command(req.command);
        send_cbor(&mut stream, &resp)
    }

    fn dispatch_command(&self, cmd: IpcCommand) -> IpcResponse {
        match cmd {
            IpcCommand::Ping => IpcResponse::Ok(IpcPayload::Pong),
            IpcCommand::Status => {
                let guard = self.vault.lock().unwrap();
                match &*guard {
                    Some(v) => {
                        let active = v.list_notes(false).map(|l| l.len()).unwrap_or(0);
                        IpcResponse::Ok(IpcPayload::Status(DaemonStatus {
                            account_id: Some(v.account_id()),
                            device_id: Some(v.device_id()),
                            active_notes_count: active,
                            is_locked: false,
                        }))
                    }
                    None => IpcResponse::Ok(IpcPayload::Status(DaemonStatus {
                        account_id: None,
                        device_id: None,
                        active_notes_count: 0,
                        is_locked: true,
                    })),
                }
            }
            IpcCommand::ListNotes { include_trashed } => {
                let guard = self.vault.lock().unwrap();
                match &*guard {
                    Some(v) => match v.list_notes(include_trashed) {
                        Ok(notes) => IpcResponse::Ok(IpcPayload::NoteList(notes)),
                        Err(e) => IpcResponse::Err(format!("List notes failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::GetNote { object_id } => {
                let guard = self.vault.lock().unwrap();
                match &*guard {
                    Some(v) => match v.get_note(object_id) {
                        Ok(note) => IpcResponse::Ok(IpcPayload::Note(note)),
                        Err(e) => IpcResponse::Err(format!("Get note failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::NewNote {
                title,
                body_md,
                tags,
                notebook_id,
            } => {
                let mut guard = self.vault.lock().unwrap();
                match &mut *guard {
                    Some(v) => match v.new_note(&title, &body_md, tags, notebook_id) {
                        Ok(id) => IpcResponse::Ok(IpcPayload::NoteCreated(id)),
                        Err(e) => IpcResponse::Err(format!("New note failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::EditNote {
                object_id,
                title,
                body_md,
                tags,
            } => {
                let mut guard = self.vault.lock().unwrap();
                match &mut *guard {
                    Some(v) => match v.edit_note(object_id, &title, &body_md, tags) {
                        Ok(op_id) => IpcResponse::Ok(IpcPayload::NoteUpdated(op_id)),
                        Err(e) => IpcResponse::Err(format!("Edit note failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::DeleteNote { object_id } => {
                let mut guard = self.vault.lock().unwrap();
                match &mut *guard {
                    Some(v) => match v.delete_note(object_id) {
                        Ok(op_id) => IpcResponse::Ok(IpcPayload::NoteDeleted(op_id)),
                        Err(e) => IpcResponse::Err(format!("Delete note failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::ShredNote { object_id } => {
                let mut guard = self.vault.lock().unwrap();
                match &mut *guard {
                    Some(v) => match v.shred_note(object_id) {
                        Ok(op_id) => IpcResponse::Ok(IpcPayload::NoteDeleted(op_id)),
                        Err(e) => IpcResponse::Err(format!("Shred note failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::Search { query } => {
                let guard = self.vault.lock().unwrap();
                match &*guard {
                    Some(v) => match v.search(&query) {
                        Ok(notes) => IpcResponse::Ok(IpcPayload::NoteList(notes)),
                        Err(e) => IpcResponse::Err(format!("Search failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::RotateKey => {
                let mut guard = self.vault.lock().unwrap();
                match &mut *guard {
                    Some(v) => {
                        let now_ms = Hlc::current_physical_ms();
                        match v.rotate_account_key(now_ms) {
                            Ok((_op, op_id, new_recovery_phrase)) => {
                                IpcResponse::Ok(IpcPayload::KeyRotated {
                                    op_id,
                                    new_recovery_phrase,
                                })
                            }
                            Err(e) => IpcResponse::Err(format!("Key rotation failed: {e}")),
                        }
                    }
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::VerifyLocal => {
                let guard = self.vault.lock().unwrap();
                match &*guard {
                    Some(v) => match v.verify_local() {
                        Ok(report) => IpcResponse::Ok(IpcPayload::Verification(report)),
                        Err(e) => IpcResponse::Err(format!("Local verification failed: {e}")),
                    },
                    None => IpcResponse::Err("Vault is locked".into()),
                }
            }
            IpcCommand::Lock => {
                let mut guard = self.vault.lock().unwrap();
                *guard = None;
                IpcResponse::Ok(IpcPayload::Locked)
            }
            IpcCommand::Unlock { passphrase } => {
                let mut guard = self.vault.lock().unwrap();
                match Vault::open(&self.db_path, passphrase.as_deref()) {
                    Ok(opened) => {
                        *guard = Some(opened);
                        IpcResponse::Ok(IpcPayload::Unlocked)
                    }
                    Err(e) => IpcResponse::Err(format!("Unlock failed: {e}")),
                }
            }
            IpcCommand::Stop => {
                self.shutdown.store(true, Ordering::SeqCst);
                IpcResponse::Ok(IpcPayload::Stopped)
            }
        }
    }
}

/// Constant-time byte array equality helper (returns 1 if equal, 0 if not).
fn subtle_slices_eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Convert 0 to 1, non-zero to 0 in constant time
    ((!diff as u16 + 1) >> 8) as u8
}

/// Local IPC Daemon Client for connecting to and invoking commands on a running daemon.
pub struct DaemonClient {
    port: u16,
    token: IpcToken,
}

impl DaemonClient {
    /// Creates a new DaemonClient configured with target port and auth token.
    #[must_use]
    pub fn new(port: u16, token: IpcToken) -> Self {
        Self { port, token }
    }

    /// Sends a command to the daemon over a fresh loopback TCP connection and receives the response.
    ///
    /// # Errors
    /// Returns `TnError` if connection, serialization, or daemon command execution fails.
    pub fn send_command(&self, command: IpcCommand) -> Result<IpcPayload, TnError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .map_err(|e| TnError::Internal(format!("Failed to connect to daemon: {e}")))?;

        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        let req = IpcRequest {
            token: self.token,
            command,
        };
        send_cbor(&mut stream, &req)?;

        let resp: IpcResponse = recv_cbor(&mut stream)?;
        match resp {
            IpcResponse::Ok(payload) => Ok(payload),
            IpcResponse::Err(err_msg) => Err(TnError::Internal(err_msg)),
        }
    }

    /// Pings the daemon for liveness.
    pub fn ping(&self) -> Result<(), TnError> {
        match self.send_command(IpcCommand::Ping)? {
            IpcPayload::Pong => Ok(()),
            other => Err(TnError::Internal(format!(
                "Unexpected ping response: {other:?}"
            ))),
        }
    }

    /// Retrieves status from the daemon.
    pub fn status(&self) -> Result<DaemonStatus, TnError> {
        match self.send_command(IpcCommand::Status)? {
            IpcPayload::Status(s) => Ok(s),
            other => Err(TnError::Internal(format!(
                "Unexpected status response: {other:?}"
            ))),
        }
    }

    /// Lists notes in the vault.
    pub fn list_notes(&self, include_trashed: bool) -> Result<Vec<NoteSummary>, TnError> {
        match self.send_command(IpcCommand::ListNotes { include_trashed })? {
            IpcPayload::NoteList(list) => Ok(list),
            other => Err(TnError::Internal(format!(
                "Unexpected list notes response: {other:?}"
            ))),
        }
    }

    /// Retrieves a note by ID.
    pub fn get_note(&self, object_id: Id16) -> Result<NoteDetail, TnError> {
        match self.send_command(IpcCommand::GetNote { object_id })? {
            IpcPayload::Note(n) => Ok(n),
            other => Err(TnError::Internal(format!(
                "Unexpected get note response: {other:?}"
            ))),
        }
    }

    /// Creates a new note.
    pub fn new_note(
        &self,
        title: String,
        body_md: String,
        tags: Vec<String>,
        notebook_id: Option<Id16>,
    ) -> Result<Id16, TnError> {
        match self.send_command(IpcCommand::NewNote {
            title,
            body_md,
            tags,
            notebook_id,
        })? {
            IpcPayload::NoteCreated(id) => Ok(id),
            other => Err(TnError::Internal(format!(
                "Unexpected new note response: {other:?}"
            ))),
        }
    }

    /// Rotates the account root key.
    pub fn rotate_key(&self) -> Result<(Id32, String), TnError> {
        match self.send_command(IpcCommand::RotateKey)? {
            IpcPayload::KeyRotated {
                op_id,
                new_recovery_phrase,
            } => Ok((op_id, new_recovery_phrase)),
            other => Err(TnError::Internal(format!(
                "Unexpected rotate response: {other:?}"
            ))),
        }
    }

    /// Runs local verification.
    pub fn verify_local(&self) -> Result<VerificationReport, TnError> {
        match self.send_command(IpcCommand::VerifyLocal)? {
            IpcPayload::Verification(rep) => Ok(rep),
            other => Err(TnError::Internal(format!(
                "Unexpected verify response: {other:?}"
            ))),
        }
    }

    /// Locks the vault.
    pub fn lock(&self) -> Result<(), TnError> {
        match self.send_command(IpcCommand::Lock)? {
            IpcPayload::Locked => Ok(()),
            other => Err(TnError::Internal(format!(
                "Unexpected lock response: {other:?}"
            ))),
        }
    }

    /// Unlocks the vault.
    pub fn unlock(&self, passphrase: Option<String>) -> Result<(), TnError> {
        match self.send_command(IpcCommand::Unlock { passphrase })? {
            IpcPayload::Unlocked => Ok(()),
            other => Err(TnError::Internal(format!(
                "Unexpected unlock response: {other:?}"
            ))),
        }
    }

    /// Stops the daemon.
    pub fn stop(&self) -> Result<(), TnError> {
        match self.send_command(IpcCommand::Stop)? {
            IpcPayload::Stopped => Ok(()),
            other => Err(TnError::Internal(format!(
                "Unexpected stop response: {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ipc_daemon_lifecycle_and_authentication() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let token_path = dir.path().join("daemon.token");

        let (vault, _phrase) = Vault::create_new(&db_path, None).unwrap();
        let token = generate_auth_token().unwrap();
        write_token_file(&token_path, &token).unwrap();
        let read_token = read_token_file(&token_path).unwrap();
        assert_eq!(token, read_token);

        let (server, listener) =
            DaemonServer::bind(Some(vault), db_path.clone(), token, 0).unwrap();
        let port = server.port();

        // Spawn daemon thread
        let shutdown = server.shutdown_signal();
        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            while !shutdown.load(Ordering::SeqCst) {
                if let Ok((stream, _)) = listener.accept() {
                    let _ = server.handle_client(stream);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        // Test Client: Authenticated ping & status
        let client = DaemonClient::new(port, token);
        assert!(client.ping().is_ok());

        let status = client.status().unwrap();
        assert!(!status.is_locked);
        assert_eq!(status.active_notes_count, 0);

        // Test Client: Create note
        let note_id = client
            .new_note(
                "Test Note".into(),
                "Hello world".into(),
                vec!["tag1".into()],
                None,
            )
            .unwrap();

        let list = client.list_notes(false).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "Test Note");

        let detail = client.get_note(note_id).unwrap();
        assert_eq!(detail.body_md, "Hello world");

        // Test Client: Key rotation via daemon
        let (rot_op_id, new_phrase) = client.rotate_key().unwrap();
        assert!(!rot_op_id.as_bytes().is_empty());
        assert_eq!(new_phrase.split_whitespace().count(), 24);

        // Test Client: Local verification via daemon
        let report = client.verify_local().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_ops, 2); // 1 put + 1 key_rotate

        // Test Client: Lock & Unlock
        client.lock().unwrap();
        let status = client.status().unwrap();
        assert!(status.is_locked);
        assert!(client.list_notes(false).is_err());

        client.unlock(None).unwrap();
        let status = client.status().unwrap();
        assert!(!status.is_locked);
        assert_eq!(client.list_notes(false).unwrap().len(), 1);

        // Test Adversary S16: Malicious client with bad token rejected fail-closed
        let bad_token = [0x99u8; 32];
        let rogue_client = DaemonClient::new(port, bad_token);
        assert!(rogue_client.ping().is_err());
        assert!(rogue_client.list_notes(false).is_err());

        // Stop daemon
        client.stop().unwrap();
        handle.join().unwrap();
    }
}
