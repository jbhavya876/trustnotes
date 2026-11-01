# TrustNotes

> **The End-to-End Encrypted, Transparency-Log-Backed, Multi-Device Verifiable Notebook**

[![CI Build](https://github.com/jbhavya876/trustnotes/actions/workflows/ci.yml/badge.svg)](https://github.com/jbhavya876/trustnotes/actions)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-FIPS%20203%20%2F%20FIPS%20204-success.svg)](docs/CRYPTO.md)
[![Safety](https://img.shields.io/badge/unsafe-forbid-brightgreen.svg)](docs/SECURITY.md)

---

## Overview

**TrustNotes** is a zero-trust, post-quantum resilient, multi-device notebook engineered from first principles. It marries end-to-end symmetric encryption with Certificate Transparency–style append-only Merkle logs, independent threshold witness cosigning, and Bitcoin OpenTimestamps epoch anchoring.

Unlike traditional cloud notebooks where service providers can read, index, or leak your private notes, TrustNotes treats the sync server as an active Byzantine adversary. The server cannot read note titles, content, tags, or attachments; cannot forge operations; and cannot silently fork or roll back history.

---

## Architectural Highlights

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Client Trust Domain                             │
│                                                                        │
│   [Desktop UI (127.0.0.1)] ◄──(Strict CSP / Localhost Only)───────────┤
│              │                                                         │
│   [Embedded HTTP Server] ────(In-Memory / Zero Remote Assets)────────┐ │
│              │                                                       │ │
│   [tn-core / Vault Engine]                                           ▼ │
│   ├── SQLite Storage (Per-Column AEAD under LocalStorageKey)    [AI Boundary]
│   ├── Inverted Full-Text Search Index (In-Memory, Zero Disk)    (Default: Off
│   ├── 1 MiB Encrypted Chunked Attachments (XChaCha20-Poly1305)   Loopback Only)
│   └── 24-Word BIP-39 Recovery & Post-Quantum Key Rotation              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
        TLS 1.3 + Asymmetric X-TN-* │ Authenticated Envelopes
        (Ed25519 + ML-DSA-65 Dual)  │ 60-Second Max Clock Skew Guard
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Server Sequencer (Untrusted Relay)                    │
│                                                                        │
│   - Operation Log Ingestion & Advisory Lock Serialization              │
│   - RFC 9162 Append-Only Merkle Tree & C2SP `tlog-tiles`               │
│   - Privacy-Preserving Epoch Tree (Hashed Account Leaf Identities)     │
│   - Quantized Timestamps (1-Hour Buckets) & Padded Ciphertexts         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
           Consistency Proofs       │ Signed Checkpoints
           (RFC 9162 §2.1.4.2)      ▼
┌────────────────────────────────────────────────────────────────────────┐
│              Independent Witness Quorum (k-of-n Threshold)             │
│                                                                        │
│   [Witness 1]                 [Witness 2]                 [Witness 3]  │
│   (Independent Host)          (Independent Host)          (Independent)│
│                                                                        │
│   Invariants: Monotonic Tree Size, Rollback Rejection, Fork Detection   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Core Security Invariants (Claims C1–C10)

| Claim | Name | Description |
| :--- | :--- | :--- |
| **C1** | **Server Zero-Knowledge** | Note contents, titles, tags, and attachments are encrypted with XChaCha20-Poly1305. The server and local SQLite files store only authenticated ciphertext. |
| **C2** | **Post-Compromise Security** | Master key rotation ($RK \to RK'$) re-wraps note keys and rotates device credentials without data loss. |
| **C3** | **Forward Secrecy** | Device enrollment and network exchanges use ephemeral Post-Quantum Hybrid KEM (X-Wing: X25519 + ML-KEM-768). |
| **C4** | **Append-Only Invariant** | Operations are committed to an RFC 9162 Merkle tree. Rollback or deletion is mathematically provable and rejected. |
| **C5** | **Fork Freedom** | Checkpoints must carry at least $k$-of-$n$ (default 2-of-3) independent witness cosignatures. Split-views are blocked. |
| **C6** | **Anti-Replay** | All requests are signed with single-use 16-byte random nonces and bounded by a strict $\pm 60$-second clock skew window. |
| **C7** | **Reproducible Builds** | Binaries are multi-builder attested and verified against dual Minisign (Ed25519) and ML-DSA-65 signatures in the Release Log. |
| **C8** | **Post-Quantum Hybrid** | FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) are composed with classical curves under a mandatory `AND` rule. |
| **C9** | **Air-Gapped Audit** | Desktop client exports standalone `.tnevidence` bundles audited completely offline via `tn-monitor audit`. |
| **C10**| **Verifiable Notebook UI** | Real-time desktop verification panel displays `verified-final` vs `provisional` state and Bitcoin OpenTimestamps anchors. |

---

## Workspace Structure (14 Crates)

The TrustNotes codebase is organized into a modular Cargo workspace where `#![forbid(unsafe_code)]` is enforced across every crate:

```text
crates/
├── tn-types       # Universal identifiers (Id16, Id32), HLC timestamps, error types, canonical CBOR
├── tn-crypto      # X-Wing KEM, ML-DSA-65, Ed25519, XChaCha20-Poly1305, Argon2id, BIP-39
├── tn-oplog       # Operation log DAG, causal dependencies, HLC ordering, CRDT convergence
├── tn-merkle      # In-tree RFC 9162 Merkle tree, inclusion proofs, consistency proofs, C2SP tiles
├── tn-tlog        # Checkpoint serialization, epoch leaf hashing, witness policy, Bitcoin OTS
├── tn-proto       # Wire schemas, X-TN-* asymmetric request signing/verification, enrollment packages
├── tn-core        # Local vault state machine, SQLite storage with per-column AEAD, attachments, AI boundary
├── tn-server      # Untrusted sequencer server, transparency publisher, advisory locks
├── tn-witness     # Standalone cosigning witness daemon, rollback and equivocation guard
├── tn-monitor     # Transparency auditor library, gossip verifier, offline evidence inspector
├── tn-desktop     # Embedded loopback desktop server, verification panel, egress allow-list
├── tn-cli         # User CLI client (init, sync, verify, export, daemon)
├── tn-adversary   # Automated active Byzantine adversary and malicious server test harness
└── tn-release     # Reproducible build verification and release transparency ceremonies
```

---

## Quickstart & Usage

### Prerequisites
- **Rust 1.70+** (stable toolchain)
- **Cargo** & **Git**

### 1. Build and Run Tests
```bash
# Clone the repository
git clone git@github.com:jbhavya876/trustnotes.git
cd trustnotes

# Verify compilation
cargo check --workspace

# Run all 164 unit, acceptance, chaos, and adversarial tests
cargo test --workspace

# Verify strict clippy compliance (0 warnings)
cargo clippy --workspace --all-targets -- -D warnings
```

### 2. Launch the Desktop Application
```bash
# Starts embedded loopback server on 127.0.0.1:<port> with zero external dependencies
cargo run -p tn-desktop
```
Open your browser to the displayed URL (`http://127.0.0.1:<port>`) to access the notebook interface, write encrypted markdown notes, attach chunked files, inspect Merkle checkpoints, and export `.tnevidence` audit bundles.

### 3. Command-Line Interface (`tn-cli`)
```bash
# Initialize a new vault with 24-word recovery phrase
cargo run -p tn-cli -- init --passphrase "my-secure-passphrase"

# Create a note
cargo run -p tn-cli -- note new --title "My Secret Note" --body "Encrypted note body"

# Run local and remote cryptographic verification
cargo run -p tn-cli -- verify

# Export audit evidence package
cargo run -p tn-cli -- export-evidence --output ./evidence.tnevidence
```

### 4. Independent Verification & Auditing
```bash
# Audit an exported evidence bundle completely offline
cargo run -p tn-monitor -- audit ./evidence.tnevidence
```

---

## Formal Verification & Compliance

- **Formal Protocol Model (TLA+)**: Located in [`docs/formal/epoch_witness.tla`](docs/formal/epoch_witness.tla), specifying rollback freedom, witness quorum consistency, and non-equivocation invariants.
- **OWASP ASVS 4.0 & CWE Top 25**: Full verification matrix available in [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md).
- **Incident Runbooks**: Emergency recovery procedures for key compromises and disaster drills in [`docs/runbooks/`](docs/runbooks/).
- **Software Bill of Materials (SBOM)**: CycloneDX 1.5 JSON SBOM in [`docs/sbom.json`](docs/sbom.json).
- **Security Audit Reports**: Full Phase 1–6 audit artifacts in [`docs/audit/run-2/REPORT.md`](docs/audit/run-2/REPORT.md).

---

## Responsible Disclosure & Security

TrustNotes enforces non-negotiable **Stop-Ship Conditions** detailed in [`docs/SECURITY.md`](docs/SECURITY.md). If you discover a vulnerability, please consult our security policy or email `security@alterblock.com`.

---

## License

Dual-licensed under either:
- **MIT License** ([LICENSE](LICENSE))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
