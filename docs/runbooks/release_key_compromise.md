# Incident Response Runbook: Release Signing Key Compromise
**Document**: `docs/runbooks/release_key_compromise.md`  
**Severity**: Critical (Software Supply Chain Security)  
**Target Entity**: Release Engineering & Binary Distribution  

---

## 1. Threat Description & Dual-Signing Invariant

- **Scenario**: An adversary extracts the release engineering private key used for Minisign or Git commit signing.
- **Supply Chain Defense Invariant**:
  - TrustNotes release bundles are **dual-signed** with both classical Minisign (Ed25519) and Post-Quantum ML-DSA-65 signatures.
  - The deterministic manifest SHA-256 (`SHA256SUMS`) must match across all reproducible build artifacts.
  - Client auto-updaters verify:
    1. Minisign Ed25519 signature against pinned release key.
    2. ML-DSA-65 quantum-resistant signature against pinned release key.
    3. Reproducible build hashes matching the transparency log binary release checkpoint.

---

## 2. Containment & Remediation Procedure

### Phase 1: Freeze Release Channels
1. Immediately freeze GitHub releases, crates.io publishing, and package repository mirrors.
2. Publish a high-severity alert to all TrustNotes distribution channels.
3. Broadcast the revoked release key fingerprint to the TrustNotes network via the transparency log metadata channel.

### Phase 2: Key Revocation & Air-Gapped Key Generation
1. Rotate the root release signing keys using air-gapped hardware security devices:
   ```bash
   tn-release init-root-keys --air-gapped --dual-scheme
   ```
2. Build an emergency patch release (e.g. `v0.1.0-rc2` / `v0.1.1`):
   - Package all binaries with clean, verified source trees.
   - Embed the hardcoded revocation list containing the compromised key fingerprint in `tn-types::release`.
   - Sign the emergency bundle with the new post-compromise key set.

### Phase 3: Binary Revocation Verification
1. Verify that `tn-release verify` strictly rejects bundles signed with the revoked key:
   ```bash
   tn-release verify --bundle old_corrupt.tar.gz --expected-key revoked_key.pub
   # MUST exit with non-zero exit code: ReleaseKeyRevoked
   ```
