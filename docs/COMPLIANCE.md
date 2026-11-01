# TrustNotes Security Compliance & Verification Matrix
**Standard**: OWASP Application Security Verification Standard (ASVS) 4.0 (Level 2) & CWE Top 25 (2023/2024)  
**Target**: TrustNotes Core Architecture, Client, Server, Witness, and Release Tooling  
**Status**: VERIFIED & PASSING (Release Candidate v0.1.0-rc1)

---

## 1. Executive Summary

TrustNotes is designed from first principles under a zero-trust, transparency-log-backed, end-to-end encrypted architecture. This document provides the formal audit and compliance evidence against:
1. **OWASP ASVS 4.0 Level 2 (Commercial Software with High Sensitivity)**
2. **CWE Top 25 Most Dangerous Software Weaknesses**
3. **Cryptographic Standards**: CNSA 2.0 (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65), RFC 8439 (XChaCha20-Poly1305), RFC 9162 (Certificate Transparency v2 Merkle Trees), C2SP `tlog-tiles` & `tlog-checkpoint`.

---

## 2. OWASP ASVS 4.0 Level 2 Matrix

| ASVS ID | Requirement Description | TrustNotes Implementation Status | Implementation Reference | Evidence / Test |
| :--- | :--- | :--- | :--- | :--- |
| **V1.1** | Secure Software Development Lifecycle | **PASS**: Multi-milestone gate protocol (M0–M7), `#![forbid(unsafe_code)]`, strict clippy `-D warnings`. | `AGENTS.md`, `.github/workflows/ci.yml` | CI build matrix, 100% test pass |
| **V2.1** | Password & Passphrase Security | **PASS**: Argon2id (m=64 MiB, t=3, p=4) with 16-byte cryptographically secure random salt. BIP-39 24-word recovery phrases. | `crates/tn-crypto/src/kdf.rs`, `recovery.rs` | `crates/tn-crypto/tests/` |
| **V2.8** | Cryptographic Authenticator Lifecycle | **PASS**: Ed25519 + ML-DSA-65 hybrid device signing keys with automated rotation ($RK \to RK'$). | `crates/tn-crypto/src/hybrid_sig.rs`, `crates/tn-core/src/vault.rs` | `m5_acceptance.rs:test_m5_full_key_rotation_roundtrip` |
| **V3.2** | Session / Request Authentication | **PASS**: Per-request asymmetric authentication (`X-TN-*` scheme) binding method, path, body SHA-256, 16-byte nonce, and timestamp with 60s max clock skew. | `crates/tn-proto/src/lib.rs` | `m7_chaos.rs:test_m7_chaos_clock_skew_enforcement` |
| **V4.1** | Access Control & Key Separation | **PASS**: Multi-tier key hierarchy (Root $\to$ Keyring $\to$ Note Key $\to$ Attachment Key). Server is untrusted and zero-knowledge. | `docs/CRYPTO.md`, `crates/tn-crypto/` | `crates/tn-core/tests/` |
| **V5.1** | Input Validation & Deserialization | **PASS**: Deterministic canonical CBOR with strict recursion depth bounding ($\le 64$), buffer-length-bounded arrays/maps, duplicate key rejection. | `crates/tn-types/src/cbor.rs` | `m7_chaos.rs:test_m7_fuzz_smoke_cbor_canonical_garbage` |
| **V6.2** | Cryptographic Algorithms | **PASS**: Post-quantum hybrid cryptography: X-Wing KEM (X25519 + ML-KEM-768), Hybrid Signatures (Ed25519 + ML-DSA-65), XChaCha20-Poly1305 AEAD. | `crates/tn-crypto/` | NIST FIPS 203/204 test vectors |
| **V7.1** | Error Handling & Logging | **PASS**: Fail-closed strongly-typed error handling (`TnError`). Zero plaintext leaks to stdout, stderr, logs, or SQLite disk. | `crates/tn-types/src/error.rs` | `m7_chaos.rs:test_m7_chaos_sqlite_disk_corruption_fail_closed` |
| **V8.3** | Sensitive Data Protection at Rest | **PASS**: Per-column AEAD encryption under `LocalStorageKey`. SQLite contains zero unencrypted note titles, bodies, tags, or keys. | `crates/tn-core/src/storage.rs` | `m1_acceptance.rs:test_m1_sqlite_canary_leak_protection` |
| **V9.1** | Communication Security | **PASS**: TLS 1.3 enforced for remote transport. Loopback IPC strictly authenticated via 256-bit bearer token and 0600 file permissions. | `crates/tn-core/src/ipc.rs` | `m5_acceptance.rs:test_m5_ipc_daemon_dispatch_and_auth` |
| **V14.1**| Build & Dependency Integrity | **PASS**: Hermetic builds, minimal locked dependencies, CycloneDX SBOM, Minisign dual-signed release bundles. | `crates/tn-release/`, `docs/sbom.json` | `m7_acceptance.rs` |

---

## 3. CWE Top 25 Vulnerability Review

| CWE ID | Weakness Name | TrustNotes Architectural Mitigation | Status |
| :--- | :--- | :--- | :--- |
| **CWE-787** | Out-of-bounds Write | Enforced `#![forbid(unsafe_code)]` in every crate. Pure safe Rust memory guarantees. | **IMMUNE** |
| **CWE-79** | Cross-Site Scripting (XSS) | Strict loopback CSP header: `default-src 'self'; script-src 'self'; object-src 'none'`. Vanilla DOM APIs (`textContent`). No remote assets. | **IMMUNE** |
| **CWE-89** | SQL Injection | `rusqlite` parameterized queries with strictly typed bind parameters (`params![...]`). Zero SQL string concatenation. | **IMMUNE** |
| **CWE-416** | Use After Free | Rust compiler borrow checker prevents all use-after-free and dangling pointer bugs. | **IMMUNE** |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | All non-GET requests require cryptographic `X-TN-*` asymmetric hybrid signature and single-use nonce. | **IMMUNE** |
| **CWE-22** | Path Traversal | Desktop server strictly serves embedded `include_str!` static assets. No user filesystem path routing. | **IMMUNE** |
| **CWE-287** | Improper Authentication | Asymmetric Ed25519 + ML-DSA-65 request signing with replay protection and 60-second clock skew limit. | **VERIFIED** |
| **CWE-798** | Use of Hard-coded Credentials | Zero hardcoded keys or salts. Keys derived dynamically via Argon2id / HKDF-SHA-256 or CSPRNG `getrandom`. | **VERIFIED** |
| **CWE-306** | Missing Authentication for Critical Function | IPC daemon commands require 256-bit high-entropy bearer token. Key rotation requires cross-signed proof of possession. | **VERIFIED** |
| **CWE-862** | Missing Authorization | AI invocation requires explicit user consent token scoped to note ID. AI egress blocked by default (`"none"`). | **VERIFIED** |
| **CWE-918** | Server-Side Request Forgery (SSRF) | AI endpoint strictly restricted to `127.0.0.1:<port>`. Desktop server intercepts and blocks non-loopback egress. | **VERIFIED** |

---

## 4. Cryptographic Agility & Audit Summary

1. **Domain Separation**: Every cryptographic operation specifies a unique, non-overlapping ASCII label (`LABEL_REGISTRY` in `docs/CRYPTO.md`).
2. **Post-Quantum Assurance**: Any compromise of classical discrete logarithm (Curve25519) is shielded by lattice-based Module-LWE (ML-KEM-768) and Module-LWE (ML-DSA-65).
3. **Fail-Closed Robustness**: Random byte fuzzing, corrupt SQLite database injection, witness partitions, and network replays all terminate cleanly with typed error invariants.
