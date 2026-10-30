# Security Audit: Architectural Assessment (M0)

## System Overview

TrustNotes is an end-to-end encrypted notes system where note confidentiality is decoupled from operator trust through verifiable transparency data structures. The repository is organized as a Cargo workspace with 13 crates, `#![forbid(unsafe_code)]`, pure-Rust crypto dependencies, and strict deterministic CBOR serialization.

## Trust Boundaries

1. **Client Storage Boundary**: Local SQLite database storing all sensitive columns encrypted under Local Storage Key (LSK). LSK resides in OS Keystore with optional Argon2id passphrase wrapping.
2. **Network Protocol Boundary**: Mutual request authentication using hybrid classical + post-quantum signatures (`X-TN-Sig`) and anti-replay nonces over TLS 1.3.
3. **Sequencer & Operator Boundary**: The untrusted server receives only padded ciphertext, hashes, and public identities. It cannot forge or alter operations without breaking Merkle proofs.
4. **Witness & Transparency Boundary**: Independent witnesses cosign epoch checkpoints according to a $k$-of-$n$ policy. Equivocation and omissions are publicly detectable by monitors (`tn-monitor`).

## Threat Model Mapping

The codebase enforces defenses against adversaries A1 through A9 (defined in `docs/THREAT_MODEL.md`) and maps each to automated adversarial scenarios S1 through S17.
