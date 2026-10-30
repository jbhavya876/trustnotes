# ADR-0001: Project Primitives and Dependency Choices

- **Status**: Accepted
- **Date**: 2026-10-31
- **Deciders**: Bhavya (AlterBlock), AI Staff Engineer
- **Consulted**: Cryptographic standards (RFC 8439, RFC 8032, FIPS 203, FIPS 204, draft-cfrg-xwing-02, RFC 9162)

---

## Context

TrustNotes requires cryptographic primitives covering classical public-key cryptography, post-quantum signatures and key encapsulation, symmetric authenticated encryption, password-based key derivation, and verifiable Merkle data structures. Section 7 of the Master Build Prompt marks several crate and standard selections as **VERIFY AT BUILD TIME**.

This ADR documents the verification of standards and crates as of Module M0 (October 2026).

---

## Decisions

### 1. Rust Stable Toolchain Version
- **Verification**: Verified via `rustc --version` and active toolchain.
- **Decision**: Pin toolchain to `1.98.1` in `rust-toolchain.toml`. Build with `--locked` in all environments.
- **Rationale**: Stable compiler guarantees reproducibility and deterministic code generation.

### 2. Symmetric Content AEAD: XChaCha20-Poly1305
- **Verification**: Evaluated `chacha20poly1305` crate (RustCrypto).
- **Decision**: Adopt `chacha20poly1305 = "0.10"` with `XChaCha20Poly1305`.
- **Rationale**: 192-bit random nonces eliminate nonce collision risk across distributed, uncoordinated devices. Pure Rust, `#![forbid(unsafe_code)]` compatible, audited by Cure53 and NCC Group.

### 3. Classical & Post-Quantum Signatures
- **Verification**: `ed25519-dalek = "2.1"` and `ml-dsa = "0.0.3"` / RustCrypto implementation of FIPS 204.
- **Decision**: Adopt `ed25519-dalek` for classical and `ml-dsa` for post-quantum ML-DSA-65.
- **Hybrid Rule**: Mandatory `AND` rule: both signatures must verify. Neither alone is sufficient.

### 4. Key Encapsulation (KEM): X-Wing
- **Verification**: X-Wing (draft-connolly-cfrg-xwing-02) combines X25519 with ML-KEM-768 inside HPKE (RFC 9180).
- **Decision**: Adopt RustCrypto `x-wing` / `hpke` crate with X-Wing KEM.
- **Contingency**: If the standalone `x-wing` crate encounters API churn, use modular composition of `x25519-dalek` + `ml-kem = "0.2"` wrapped in our internal `tn-crypto::kem` abstraction.

### 5. Strict Deterministic CBOR Codec
- **Verification**: `ciborium` vs. `minicbor`.
- **Decision**: Use `ciborium` wrapped inside an internal strict decoder in `tn-types`.
- **Strict Decoders**: The wrapper enforces:
  - Rejection of non-canonical shortest integer encodings.
  - Rejection of duplicate map keys.
  - Rejection of indefinite-length strings or arrays.
  - Rejection of trailing extraneous bytes.

### 6. BIP-39 Wordlist Encoding
- **Verification**: `bip39 = "2.1"` crate.
- **Decision**: Use solely as a canonical 24-word presentation format for the 256-bit Recovery Key. No hierarchical deterministic (HD) wallet paths or cryptocurrency key derivations are used.

### 7. Password KDF: Argon2id
- **Verification**: `argon2 = "0.5"` crate (RustCrypto).
- **Decision**: Desktop default profile $m=256\text{ MiB}, t=3, p=1$. Floor profile $m=64\text{ MiB}, t=3, p=1$. CI test profile $m=16\text{ MiB}, t=1, p=1$.

---

## Consequences

- No external C/C++ crypto libraries (no OpenSSL, no libsodium, no SQLCipher).
- Pure Rust dependency graph satisfying `#![forbid(unsafe_code)]`.
- Defense-in-depth against future quantum computers via hybrid classical + post-quantum algorithms.
