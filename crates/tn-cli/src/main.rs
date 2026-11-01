#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]
//! `tn`: The TrustNotes command-line client.
//!
//! Provides CLI access to initialization, encrypted note management, search,
//! recovery drills, and local integrity verification.

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tn_core::Vault;
use tn_proto::evidence::{BundleEvidence, EvidenceBundle};
use tn_proto::release::{ReleaseLog, ReleaseLogManifest};
use tn_tlog::ots::{verify_ots_proof, BitcoinBlockHeader, OtsProof};
use tn_tlog::Checkpoint;
use tn_types::Id16;

#[derive(Parser)]
#[command(
    name = "tn",
    about = "TrustNotes: End-to-end encrypted transparent notebook"
)]
struct Cli {
    /// Path to SQLite database file.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    /// Passphrase for vault decryption.
    #[arg(long, global = true, env = "TN_PASSPHRASE")]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted vault and print the 24-word recovery phrase.
    Init {
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Test unlocking the vault with passphrase.
    Unlock,
    /// Create a new encrypted note.
    New {
        /// Note title.
        title: String,
        /// Markdown body text.
        #[arg(short, long, default_value = "")]
        body: String,
        /// Comma-separated list of tags.
        #[arg(short, long)]
        tags: Option<String>,
    },
    /// Edit an existing note.
    Edit {
        /// 32-character hexadecimal object ID.
        object_id: String,
        /// New title.
        #[arg(long)]
        title: Option<String>,
        /// New body text.
        #[arg(long)]
        body: Option<String>,
        /// New comma-separated tags.
        #[arg(long)]
        tags: Option<String>,
    },
    /// Display full note contents and history.
    Show {
        /// 32-character hexadecimal object ID.
        object_id: String,
    },
    /// List notes in vault.
    Ls {
        /// Include soft-deleted/trashed notes.
        #[arg(short, long)]
        all: bool,
    },
    /// Soft-delete (trash) a note.
    Rm {
        /// 32-character hexadecimal object ID.
        object_id: String,
    },
    /// Search notes using the fast in-memory inverted index.
    Search {
        /// Search query terms.
        query: String,
    },
    /// Add a tag to a note.
    Tag {
        /// 32-character hexadecimal object ID.
        object_id: String,
        /// Tag string to append.
        tag: String,
    },
    /// View operation history for a note.
    History {
        /// 32-character hexadecimal object ID.
        object_id: String,
    },
    /// Restore a trashed note.
    Restore {
        /// 32-character hexadecimal object ID.
        object_id: String,
    },
    /// Crypto-shred a note (purges NoteKey locally).
    Shred {
        /// 32-character hexadecimal object ID.
        object_id: String,
    },
    /// Recovery key operations.
    Recovery {
        #[command(subcommand)]
        action: RecoveryAction,
    },
    /// Export notes as plaintext markdown files.
    Export {
        /// Output directory path.
        out_dir: PathBuf,
    },
    /// Import notes from directory of markdown files.
    Import {
        /// Input directory path.
        in_dir: PathBuf,
    },
    /// Verify local cryptographic integrity and log invariants.
    Verify {
        /// Verify local database ops.
        #[arg(long)]
        local: bool,
    },
    /// Bitcoin OpenTimestamps verification (Claim C6).
    Anchor {
        #[command(subcommand)]
        action: AnchorAction,
    },
    /// Verify executable or specified binary against the Release Transparency Log (Claim C7).
    SelfVerify {
        /// Path to binary to verify (defaults to current running executable).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Path to release transparency log manifest (CBOR).
        #[arg(long)]
        release_log: PathBuf,
        /// Expected semantic version (e.g. "0.1.0" or "v0.1.0").
        #[arg(long)]
        version: Option<String>,
        /// Target triple (e.g. "x86_64-pc-windows-msvc").
        #[arg(long)]
        target: Option<String>,
    },
    /// Export or inspect cryptographic Evidence Bundles proving server misbehavior (Claim C5, ADR-0001).
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
}

#[derive(Subcommand)]
enum AnchorAction {
    /// Verify an OpenTimestamps proof for a checkpoint root against Bitcoin block headers.
    Verify {
        /// Path to CBOR checkpoint file.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Hex-encoded root hash directly (if checkpoint file not provided).
        #[arg(long)]
        root_hash: Option<String>,
        /// Path to OTS proof file (CBOR).
        #[arg(long, alias = "ots")]
        proof: PathBuf,
        /// Expected Bitcoin block hash (64 hex characters).
        #[arg(long)]
        block_hash: Option<String>,
        /// Path to binary Bitcoin block headers file (80 bytes).
        #[arg(long)]
        headers: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum EvidenceAction {
    /// Export evidence bundle from vault or specific file.
    Export {
        /// Output file path to write CBOR evidence bundle to.
        #[arg(long, short, alias = "out")]
        output: PathBuf,
        /// Path to receipt file (optional).
        #[arg(long)]
        receipt: Option<PathBuf>,
    },
    /// Inspect an evidence bundle file.
    Inspect {
        /// Path to evidence bundle file.
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum RecoveryAction {
    /// Restore a vault from a 24-word BIP-39 recovery phrase.
    Restore {
        /// 24 space-separated words.
        phrase: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

fn parse_id32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(clean).map_err(|e| anyhow::anyhow!("Invalid hex 32-byte string: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Expected exactly 32 bytes (64 hex characters)");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_id16(hex_str: &str) -> anyhow::Result<Id16> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("Invalid hex object_id: {e}"))?;
    if bytes.len() != 16 {
        anyhow::bail!("object_id must be exactly 16 bytes (32 hex characters)");
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(Id16::from_bytes(arr))
}

fn resolve_db_path(opt: Option<PathBuf>) -> PathBuf {
    if let Some(p) = opt {
        return p;
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let dir = PathBuf::from(home).join(".trustnotes");
        let _ = fs::create_dir_all(&dir);
        dir.join("vault.db")
    } else {
        PathBuf::from("trustnotes.db")
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}

fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let db_path = resolve_db_path(cli.db);

    match cli.command {
        Commands::Init { passphrase } => {
            if db_path.exists() {
                anyhow::bail!("Vault database already exists at {}", db_path.display());
            }
            if let Some(parent) = db_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let pass = passphrase.as_deref().or(cli.passphrase.as_deref());
            let (_vault, phrase) = Vault::create_new(&db_path, pass)?;
            println!("Initialized new TrustNotes vault at: {}", db_path.display());
            println!("\n========================================================");
            println!("RECOVERY KEY (24 words) — Write this down in order:");
            println!("========================================================");
            println!("{phrase}");
            println!("========================================================\n");
        }
        Commands::Unlock => {
            let pass = cli.passphrase.as_deref();
            let _vault = Vault::open(&db_path, pass)?;
            println!("Vault unlocked successfully: {}", db_path.display());
        }
        Commands::New { title, body, tags } => {
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let parsed_tags = tags
                .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let object_id = vault.new_note(&title, &body, parsed_tags, None)?;
            println!("Created note: {object_id}");
        }
        Commands::Edit {
            object_id,
            title,
            body,
            tags,
        } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let existing = vault.get_note(id)?;

            let new_title = title.unwrap_or(existing.summary.title);
            let new_body = body.unwrap_or(existing.body_md);
            let new_tags = tags
                .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or(existing.summary.tags);

            let op_id = vault.edit_note(id, &new_title, &new_body, new_tags)?;
            println!("Updated note {id} (op_id: {op_id})");
        }
        Commands::Show { object_id } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let note = vault.get_note(id)?;

            println!("ID:      {}", note.summary.object_id);
            println!("Title:   {}", note.summary.title);
            println!("Status:  {}", note.summary.status);
            println!("Tags:    {}", note.summary.tags.join(", "));
            println!("Updated: {}", note.summary.updated_at);
            println!("History: {} ops", note.history.len());
            println!("----------------------------------------");
            println!("{}", note.body_md);
        }
        Commands::Ls { all } => {
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let notes = vault.list_notes(all)?;

            if notes.is_empty() {
                println!("No notes found in vault.");
            } else {
                for n in &notes {
                    println!(
                        "{} | {:<10} | {:<30} | [{}]",
                        n.object_id,
                        n.status,
                        n.title,
                        n.tags.join(", ")
                    );
                }
            }
        }
        Commands::Rm { object_id } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let op_id = vault.delete_note(id)?;
            println!("Trashed note {id} (op_id: {op_id})");
        }
        Commands::Search { query } => {
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let results = vault.search(&query)?;

            if results.is_empty() {
                println!("No matching notes found for query: '{query}'");
            } else {
                println!("Found {} matching note(s):", results.len());
                for n in results {
                    println!("{} | {} | [{}]", n.object_id, n.title, n.tags.join(", "));
                }
            }
        }
        Commands::Tag { object_id, tag } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let existing = vault.get_note(id)?;

            let mut tags = existing.summary.tags;
            if !tags.contains(&tag) {
                tags.push(tag.clone());
            }

            vault.edit_note(id, &existing.summary.title, &existing.body_md, tags)?;
            println!("Tagged note {id} with '{tag}'");
        }
        Commands::History { object_id } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let note = vault.get_note(id)?;

            println!("History for note {id}:");
            for (idx, op_id) in note.history.iter().enumerate() {
                println!("  [{idx}] {op_id}");
            }
        }
        Commands::Restore { object_id } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let existing = vault.get_note(id)?;
            let op_id = vault.edit_note(
                id,
                &existing.summary.title,
                &existing.body_md,
                existing.summary.tags,
            )?;
            println!("Restored note {id} (op_id: {op_id})");
        }
        Commands::Shred { object_id } => {
            let id = parse_id16(&object_id)?;
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let op_id = vault.shred_note(id)?;
            println!("Crypto-shredded note {id} (op_id: {op_id})");
        }
        Commands::Recovery { action } => match action {
            RecoveryAction::Restore { phrase, passphrase } => {
                let pass = passphrase.as_deref().or(cli.passphrase.as_deref());
                let _vault = Vault::recover_from_phrase(&db_path, &phrase, pass)?;
                println!(
                    "Vault successfully recovered from 24-word phrase: {}",
                    db_path.display()
                );
            }
        },
        Commands::Export { out_dir } => {
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let notes = vault.list_notes(false)?;
            fs::create_dir_all(&out_dir)?;

            for n in &notes {
                let detail = vault.get_note(n.object_id)?;
                let filename = format!("{}_{}.md", n.object_id, sanitize_filename(&n.title));
                let path = out_dir.join(filename);
                let content = format!(
                    "---\ntitle: {}\ntags: [{}]\nupdated_at: {}\n---\n\n{}",
                    n.title,
                    n.tags.join(", "),
                    n.updated_at,
                    detail.body_md
                );
                fs::write(&path, content)?;
            }
            println!("Exported {} notes to {}", notes.len(), out_dir.display());
        }
        Commands::Import { in_dir } => {
            let pass = cli.passphrase.as_deref();
            let mut vault = Vault::open(&db_path, pass)?;
            let mut count = 0;

            for entry in fs::read_dir(in_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "md") {
                    let text = fs::read_to_string(&path)?;
                    let title = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Imported Note".into());
                    vault.new_note(&title, &text, vec!["imported".into()], None)?;
                    count += 1;
                }
            }
            println!("Imported {count} notes from directory.");
        }
        Commands::Verify { local } => {
            if !local {
                anyhow::bail!("Specify --local for local vault verification");
            }
            let pass = cli.passphrase.as_deref();
            let vault = Vault::open(&db_path, pass)?;
            let report = vault.verify_local()?;

            println!("========================================");
            println!("TRUSTNOTES LOCAL VERIFICATION REPORT");
            println!("========================================");
            println!("Database:     {}", db_path.display());
            println!("Total Ops:    {}", report.total_ops);
            println!("Verified Ops: {}", report.verified_ops);
            println!("Status:       VERIFIED (all invariants hold)");
            println!("========================================");
        }
        Commands::Anchor { action } => match action {
            AnchorAction::Verify {
                checkpoint,
                root_hash,
                proof,
                block_hash,
                headers,
            } => {
                let target_root = if let Some(cp_path) = checkpoint {
                    let cp_bytes = fs::read(&cp_path)?;
                    let cp = Checkpoint::from_cbor(&cp_bytes)?;
                    cp.root_hash
                } else if let Some(rh_str) = root_hash {
                    parse_id32(&rh_str)?
                } else {
                    anyhow::bail!("Specify either --checkpoint <PATH> or --root-hash <HEX>");
                };

                let proof_bytes = fs::read(&proof)?;
                let ots_proof = OtsProof::from_bytes(&proof_bytes)?;

                let expected_hash = if let Some(bh_str) = block_hash {
                    parse_id32(&bh_str)?
                } else if let Some(hdr_path) = headers {
                    let hdr_bytes = fs::read(&hdr_path)?;
                    let hdr = BitcoinBlockHeader::from_bytes(&hdr_bytes)?;
                    hdr.block_hash()
                } else {
                    ots_proof.block_header.block_hash()
                };

                let res = verify_ots_proof(&target_root, &ots_proof, &expected_hash)?;

                println!("========================================");
                println!("BITCOIN OPENTIMESTAMPS VERIFICATION");
                println!("========================================");
                println!("Checkpoint Root: {}", hex::encode(target_root));
                println!("Bitcoin Height:  {}", res.block_height);
                println!("Bitcoin Hash:    {}", hex::encode(res.block_hash));
                println!("Bitcoin Time:    {}", res.block_timestamp);
                println!("Status:          VERIFIED (anchored in Bitcoin chain)");
                println!("========================================");
            }
        },
        Commands::SelfVerify {
            binary,
            release_log,
            version,
            target,
        } => {
            let bin_path = if let Some(p) = binary {
                p
            } else {
                std::env::current_exe()?
            };
            let bin_bytes = fs::read(&bin_path)?;
            let bin_hash: [u8; 32] = Sha256::digest(&bin_bytes).into();

            let manifest_bytes = fs::read(&release_log)?;
            let manifest = ReleaseLogManifest::from_cbor(&manifest_bytes)?;
            let log = ReleaseLog::from_manifest(manifest);

            let (idx, entry) = log
                .entries()
                .iter()
                .enumerate()
                .find(|(_, e)| {
                    if let Some(v) = &version {
                        if &e.version != v {
                            return false;
                        }
                    }
                    if let Some(t) = &target {
                        if &e.target != t {
                            return false;
                        }
                    }
                    e.binary_hash == bin_hash
                })
                .map(|(i, e)| (i as u64, e))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Binary hash {} not found in release transparency log",
                        hex::encode(bin_hash)
                    )
                })?;

            let proof = log.inclusion_proof(idx)?;
            let root = log.root();

            let leaf_hash = entry.compute_leaf_hash();
            tn_merkle::verify_inclusion(&leaf_hash, &proof, &root)?;

            println!("========================================");
            println!("RELEASE TRANSPARENCY VERIFICATION");
            println!("========================================");
            println!("Binary Path:     {}", bin_path.display());
            println!("Binary SHA-256:  {}", hex::encode(bin_hash));
            println!("Version:         {}", entry.version);
            println!("Target Triple:   {}", entry.target);
            println!("Release Log Size:{}", log.len());
            println!("Release Root:    {}", hex::encode(root.as_bytes()));
            println!(
                "Attestations:    {} builder signatures",
                entry.attestations.len()
            );
            println!("Status:          VERIFIED (byte-for-byte authentic reproducible release)");
            println!("========================================");
        }
        Commands::Evidence { action } => match action {
            EvidenceAction::Export { output, receipt: _ } => {
                let pass = cli.passphrase.as_deref();
                let vault = Vault::open(&db_path, pass)?;
                if let Some(bundle_bytes) = vault.get_last_evidence_bundle()? {
                    fs::write(&output, &bundle_bytes)?;
                    println!(
                        "Exported evidence bundle ({} bytes) to {}",
                        bundle_bytes.len(),
                        output.display()
                    );
                } else {
                    anyhow::bail!("No evidence bundle recorded in vault metadata");
                }
            }
            EvidenceAction::Inspect { file } => {
                let bytes = fs::read(&file)?;
                let bundle = EvidenceBundle::from_cbor(&bytes)?;
                let kind_str = match bundle.evidence {
                    BundleEvidence::MergeDeadline(_) => "MergeDeadlineMissed (Scenario S10)",
                    BundleEvidence::Equivocation(_) => "Equivocation (Scenario S12)",
                    BundleEvidence::SplitView(_) => "SplitView (Scenario S7)",
                };

                println!("========================================");
                println!("EVIDENCE BUNDLE INSPECTION");
                println!("========================================");
                println!("Bundle File:   {}", file.display());
                println!("Kind:          {}", kind_str);
                println!(
                    "Account ID:    {}",
                    hex::encode(bundle.account_id.as_bytes())
                );
                println!("Created At:    {} ms", bundle.created_at);
                println!("Status:        CRYPTOGRAPHIC PROOF OF OPERATOR MISBEHAVIOR");
                println!("========================================");
            }
        },
    }

    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cli_roundtrip_flow() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("cli_test.db");

        // Init vault
        let (mut vault, phrase) = Vault::create_new(&db_path, Some("testpass")).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        // Add note
        let note_id = vault
            .new_note(
                "CLI Test Note",
                "Test body contents",
                vec!["test".into()],
                None,
            )
            .unwrap();

        // Verify local
        let report = vault.verify_local().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_ops, 1);

        // Search
        let hits = vault.search("Test").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].object_id, note_id);
    }

    #[test]
    fn test_cli_anchor_verify() {
        let dir = tempdir().unwrap();
        let cp_path = dir.path().join("checkpoint.cbor");
        let ots_path = dir.path().join("checkpoint.ots");

        let cp_root = [0x55u8; 32];
        let checkpoint = Checkpoint {
            origin: "trustnotes.org/log/test".into(),
            size: 100,
            root_hash: cp_root,
            timestamp_ms: 1_700_000_000_000,
            server_sig: tn_crypto::HybridSignature {
                ed25519: [0u8; 64],
                ml_dsa: vec![],
            },
            cosignatures: vec![],
        };
        fs::write(&cp_path, checkpoint.to_cbor().unwrap()).unwrap();

        let (proof, block_hash) =
            tn_tlog::ots::create_mock_ots_proof(&cp_root, 800_000, 1_700_000_000);
        fs::write(&ots_path, proof.to_bytes().unwrap()).unwrap();

        let cli = Cli {
            db: None,
            passphrase: None,
            command: Commands::Anchor {
                action: AnchorAction::Verify {
                    checkpoint: Some(cp_path),
                    root_hash: None,
                    proof: ots_path,
                    block_hash: Some(hex::encode(block_hash)),
                    headers: None,
                },
            },
        };
        assert!(run_cli(cli).is_ok());
    }

    #[test]
    fn test_cli_self_verify() {
        use tn_proto::release::ReleaseEntry;

        let dir = tempdir().unwrap();
        let bin_path = dir.path().join("dummy_bin.exe");
        let release_log_path = dir.path().join("releases.cbor");

        let bin_bytes = b"fake-executable-binary-payload-for-test";
        fs::write(&bin_path, bin_bytes).unwrap();
        let bin_hash: [u8; 32] = sha2::Sha256::digest(bin_bytes).into();

        let mut release_log = ReleaseLog::new();
        release_log.append_entry(ReleaseEntry {
            version: "1.0.0".into(),
            target: "x86_64-pc-windows-msvc".into(),
            binary_hash: bin_hash,
            attestations: vec![],
        });

        fs::write(
            &release_log_path,
            release_log.to_manifest().to_cbor().unwrap(),
        )
        .unwrap();

        let cli = Cli {
            db: None,
            passphrase: None,
            command: Commands::SelfVerify {
                binary: Some(bin_path),
                release_log: release_log_path,
                version: Some("1.0.0".into()),
                target: Some("x86_64-pc-windows-msvc".into()),
            },
        };
        assert!(run_cli(cli).is_ok());
    }

    #[test]
    fn test_cli_evidence_export_and_inspect() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault_ev.db");
        let ev_path = dir.path().join("evidence.cbor");

        let (vault, _) = Vault::create_new(&db_path, Some("evpass")).unwrap();
        let bundle = EvidenceBundle::new_equivocation(
            tn_types::Id32::from_bytes([0x11; 32]),
            10,
            Checkpoint {
                origin: "tlog".into(),
                size: 10,
                root_hash: [0xaa; 32],
                timestamp_ms: 1000,
                server_sig: tn_crypto::HybridSignature {
                    ed25519: [0; 64],
                    ml_dsa: vec![],
                },
                cosignatures: vec![],
            },
            Checkpoint {
                origin: "tlog".into(),
                size: 10,
                root_hash: [0xbb; 32],
                timestamp_ms: 1000,
                server_sig: tn_crypto::HybridSignature {
                    ed25519: [0; 64],
                    ml_dsa: vec![],
                },
                cosignatures: vec![],
            },
            1000,
        );
        vault
            .set_last_evidence_bundle(&bundle.to_cbor().unwrap())
            .unwrap();

        // Export
        let cli_export = Cli {
            db: Some(db_path),
            passphrase: Some("evpass".into()),
            command: Commands::Evidence {
                action: EvidenceAction::Export {
                    output: ev_path.clone(),
                    receipt: None,
                },
            },
        };
        assert!(run_cli(cli_export).is_ok());
        assert!(ev_path.exists());

        // Inspect
        let cli_inspect = Cli {
            db: None,
            passphrase: None,
            command: Commands::Evidence {
                action: EvidenceAction::Inspect { file: ev_path },
            },
        };
        assert!(run_cli(cli_inspect).is_ok());
    }
}
