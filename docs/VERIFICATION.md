# TrustNotes Verification Guide (VERIFICATION.md)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Scope & Objective

This document is an independent third party's operational guide to cryptographically auditing a TrustNotes deployment. Under **Claim C10 (Third-Party Auditability)**, any external observer or security researcher can verify the integrity of the server's history, release binaries, and witness cosignatures without operator cooperation or access to user keys.

---

## 2. Claims Covered & Verification Mechanics

| Claim | Target Property | Public Audit Tool | Verification Procedure |
|-------|-----------------|-------------------|------------------------|
| **C3** History Integrity | Server cannot modify, delete, reorder, or inject ops | `tn-monitor` / `tn verify` | Verify RFC 9162 Merkle inclusion and consistency proofs against signed checkpoints. |
| **C4** No Split View | Server cannot present diverging views to different users or devices | `tn-monitor` / device gossip | Collect checkpoints from independent witnesses ($k$-of-$n$); compare roots. |
| **C5** Accountable Promises | Missing inclusion past Merge Deadline is cryptographic proof of misbehavior | `tn evidence export` / `tn-monitor` | Match signed Receipt (`mmd_epoch`) against witnessed checkpoints covering that epoch. |
| **C6** Time Evidence | Checkpoints anchored to Bitcoin via OpenTimestamps | `tn anchor verify` | Offline validation of OTS calendar proof against user-supplied Bitcoin block headers. [M4] |
| **C7** Release Integrity | Release binaries are reproducible and recorded in transparency log | `tn-release` / `tn self-verify` | Byte-for-byte build comparison; verify inclusion proof in release log. [M4] |

---

## 3. Tool Installation & Setup

```bash
# Build the auditing tools from source using pinned toolchain
cargo build --locked --bin tn-monitor --bin tn
```

Required public parameters (available in `deploy/public_keys.toml` or `GET /v1/server-info`):
- Server classical signing key: `server_ed25519_pubkey`
- Server post-quantum signing key: `server_mldsa65_pubkey`
- Witness identity keys: `witness_keys` ($n$ entries, threshold $k$)
- Log origin URI: `log_origin`

---

## 4. Step-by-Step Verification Procedures

### 4.1 Verifying History Integrity (C3)

1. **Query Checkpoint**: Fetch latest checkpoint with cosignatures:
   ```bash
   curl -s https://<server>/v1/log/checkpoint > checkpoint.json
   ```
2. **Verify Hybrid Signature**: Assert both the Ed25519 and ML-DSA-65 signatures are valid over canonical checkpoint text.
3. **Verify Witness Cosignatures**: Assert at least $k$ distinct pinned witness cosignatures are present and valid.
4. **Verify Consistency**: Fetch consistency proof from previous checkpoint $N_0$ to current $N$:
   ```bash
   curl -s "https://<server>/v1/log/proof/consistency?from=${N0}&to=${N}" > proof.json
   ```
   Run `tn-monitor verify-consistency --from ${N0} --to ${N} --proof proof.json`.

### 4.2 Verifying Accountable Promises (C5)

When a client holds a receipt with `op_id` and `mmd_epoch`:
1. Check that the global log has reached epoch $E \ge \text{mmd\_epoch}$.
2. Request epoch inclusion proof:
   ```bash
   curl -s "https://<server>/v1/epoch/${E}/proof" -H "X-TN-Device: ..." -H "X-TN-Sig: ..."
   ```
3. If the server fails to supply proof, or if the account is omitted from the epoch tree, export an Evidence Bundle:
   ```bash
   tn evidence export --receipt receipt.cbor --output evidence.cbor
   ```
4. Third parties verify the bundle offline:
   ```bash
   tn-monitor verify-evidence --bundle evidence.cbor --server-key <PUBKEY>
   ```

### 4.3 Verifying Bitcoin Time Anchoring (C6) [M4]

*To be completed in Module M4.*
Anchoring proofs (`.ots`) are published alongside checkpoint tiles. Users verify timestamping offline without contacting third-party calendars:
```bash
tn anchor verify --checkpoint checkpoint.cbor --ots checkpoint.ots --headers bitcoin_headers.dat
```

### 4.4 Verifying Release Reproducibility (C7) [M4]

*To be completed in Module M4.*
Every release binary is built independently by two builders and committed to the release transparency log:
```bash
tn self-verify --binary target/release/tn
```

---

## 5. Limits & Non-Assumptions

- **Detection Latency**: A split-view attack or omission is detected upon the next witness polling cycle or gossip sync.
- **Availability**: Verifying integrity does not force the server to serve data; it ensures that any withholding or tampering cannot occur silently.
