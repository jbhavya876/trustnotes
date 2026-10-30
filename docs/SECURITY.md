# Security Policy (SECURITY.md)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| `0.1.0-dev` (main) | Yes | Current active development branch |
| `< 0.1.0` | No | Prototype pre-releases |

---

## 2. Reporting a Vulnerability

We welcome security reviews from researchers, cryptographers, and engineers. If you discover a vulnerability or cryptographic defect in TrustNotes:

1. **Email**: Send details to `security@alterblock.com` with subject `[TrustNotes Security Report]`.
2. **PGP / Age Encryption**: Use the AlterBlock security team public key published at `https://alterblock.com/security.pub`.
3. **Acknowledgment**: We acknowledge all reports within **48 hours**.
4. **Resolution SLA**: Critical findings are triaged and patched within 14 days before any public disclosure.
5. **Credit**: Researchers who follow responsible disclosure will be credited in release notes and on our hall of fame.

---

## 3. Stop-Ship Conditions (Non-Negotiable)

Any of the following conditions constitutes an automatic release blocker. No release artifact may be tagged or published if any condition is present:

1. **Undetected Adversary Scenario**: Any scenario in the adversarial test suite (S1 through S17) fails to be detected with its exact typed error.
2. **Plaintext Canary Leakage**: A canary string is discovered on disk, in temp directories, in server database dumps, in server logs, or in captured wire requests.
3. **Unverified Fallback Path**: Any code path that accepts unverified data when a cryptographic verification, checkpoint check, or witness policy check fails.
4. **Key or Nonce Reuse**: Any duplicate (key, nonce) pair generated or permitted in AEAD encryption.
5. **Secrets in Logs or Snapshots**: Any private key, recovery key, note key, or secret material appearing in `Debug` outputs, error messages, tracing logs, or test snapshots.
6. **Non-Reproducible Build**: Two independent container builds produce differing SHA-256 hashes for any release artifact.
7. **Unresolved Critical or High Finding**: Any open finding from `cargo audit`, `cargo deny`, or static security audits.
8. **Claim Without Test**: Any of the 10 security claims (C1–C10) lacking an automated test in `docs/TRACEABILITY.md`.

---

## 4. Cryptographic Hygiene Rules

- **`#![forbid(unsafe_code)]`**: Enforced on every first-party crate in the Cargo workspace.
- **Constant-Time Verification**: All comparisons of MACs, signatures, hashes, and authentication tags use `subtle::ConstantTimeEq`.
- **Zeroization**: All secret structs implement `Zeroize` and `ZeroizeOnDrop`.
- **No Novel Cryptography**: Standard primitives only (RFC 8439, RFC 8032, FIPS 204, RFC 9162).
