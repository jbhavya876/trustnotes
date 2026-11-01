# TrustNotes Third-Party Security Review & Audit Package
**Release Candidate**: v0.1.0-rc1  
**Target Codebase**: `trustnotes` (Multi-crate Cargo Workspace)  
**Date**: November 2026  
**Auditor Guide**: End-to-End Cryptographic Protocol, Threat Model & Code Audit  

---

## 1. Codebase Overview & Security Perimeter

TrustNotes is a multi-device notebook with end-to-end encryption, backed by an RFC 9162 append-only transparency log with independent witness cosigning.

### Core Architectural Axioms
1. **Server Zero-Knowledge (Claim C1)**: The server never observes note titles, bodies, tags, or keys in plaintext. All note operations are encrypted with XChaCha20-Poly1305.
2. **Post-Quantum Resilience (Claim C8)**: Hybrid KEM (X-Wing: X25519 + ML-KEM-768) and Hybrid Signatures (Ed25519 + ML-DSA-65) ensure confidentiality and authenticity against quantum adversaries.
3. **Transparency & Fork Freedom (Claim C10, ADR-0001)**: The transparency log emits signed checkpoints cosigned by at least $K$ independent witnesses (2-of-3 threshold). Clients reject any un-cosigned or equivocating log head.
4. **Memory Safety**: `#![forbid(unsafe_code)]` enforced across all 14 workspace crates.

---

## 2. Directory Layout & Key Modules

| Path | Crate | Primary Function & Audit Scope |
| :--- | :--- | :--- |
| `crates/tn-types/` | `tn-types` | Common primitives (`Id16`, `Id32`, `Hlc`), strongly-typed `TnError`, canonical RFC 8949 CBOR encoder/decoder. |
| `crates/tn-crypto/` | `tn-crypto` | Post-quantum hybrid cryptography, Argon2id, HKDF-SHA-256, XChaCha20-Poly1305, BIP-39 recovery. |
| `crates/tn-oplog/` | `tn-oplog` | Operation log definitions (`Op`, `OpHeader`, `Payload`), causal dependency graph (`deps`), CRDT convergence. |
| `crates/tn-merkle/` | `tn-merkle` | RFC 9162 Merkle tree, inclusion proofs, consistency proofs, C2SP `tlog-tiles`. |
| `crates/tn-tlog/` | `tn-tlog` | Checkpoint representation, epoch leaf hashing, witness policy verification, Bitcoin OpenTimestamps anchors. |
| `crates/tn-proto/` | `tn-proto` | Network protocol schemas, asymmetric `X-TN-*` request signing & verification, enrollment packages. |
| `crates/tn-core/` | `tn-core` | Local vault state machine, SQLite storage with per-column AEAD, chunked attachments, AI security boundary, local IPC daemon. |
| `crates/tn-server/` | `tn-server` | Untrusted sequencer, log publisher, receipt issuer. |
| `crates/tn-witness/` | `tn-witness` | Independent cosigning witness node, consistency verifier, rollback & equivocation guard. |
| `crates/tn-monitor/` | `tn-monitor` | Transparency log monitor, gossip verifier, offline `.tnevidence` audit engine. |
| `crates/tn-cli/` | `tn-cli` | Command-line management interface. |
| `crates/tn-desktop/`| `tn-desktop` | Embedded desktop web client, verification panel, egress allow-list. |
| `crates/tn-adversary/`| `tn-adversary` | Adversarial test suite simulating malicious server and Byzantine attacks. |
| `crates/tn-release/`| `tn-release` | Deterministic reproducible release packaging and dual Minisign/ML-DSA verification. |

---

## 3. Cryptographic Label Registry (from `docs/CRYPTO.md`)

Every cryptographic primitive uses explicit domain separation to prevent cross-protocol attacks:

- `tn/v1/lsk\0`: LocalStorageKey derivation (Argon2id salt / passphrase).
- `tn/v1/vault-key\0`: VaultKey derivation from RootKey.
- `tn/v1/wrap-nk\0`: NoteKey wrapping under VaultKey.
- `tn/v1/attachment\0`: Attachment chunk key derivation under NoteKey.
- `tn/v1/sig/op`: Op header hybrid signing.
- `tn/v1/sig/receipt`: Server receipt hybrid signing.
- `tn/v1/epoch-leaf`: Epoch tree leaf privacy hashing.
- `tn/v1/request/sig`: HTTP request envelope hybrid signing (`X-TN-*`).

---

## 4. Verification & Audit Test Commands

To build and independently verify the entire codebase:

```bash
# 1. Check workspace compilation and zero warnings
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings

# 2. Check code formatting
cargo fmt --check

# 3. Run all unit and integration tests (160+ tests)
cargo test --workspace

# 4. Run Chaos & Fault-Injection test suite
cargo test -p tn-core --test m7_chaos

# 5. Run Adversarial security test suite
cargo test -p tn-adversary

# 6. Verify reproducible build & release package
cargo run -p tn-release -- --version 0.1.0-rc1
```
