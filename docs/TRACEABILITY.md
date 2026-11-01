# Claims and Adversary Traceability Matrix (TRACEABILITY.md)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Ten Security Claims (C1–C10)

Every claim made by TrustNotes must be backed by automated test suites.

| Claim ID | Claim Description | Advancing Modules | Automated Test Verification | Status |
|----------|-------------------|-------------------|-----------------------------|--------|
| **C1** | **Content confidentiality**: Operator cannot read note bodies, titles, tags, notebook names, or attachment names. | M1, M2, M6 | Local canary test (`tn-core`), wire-format review, whole-system DB canary sweep (`tn-server`), 1 MiB chunked AEAD (`tn-core::attachment`), AI boundary & egress allow-list (`tn-desktop`). | **Verified (M6)** |
| **C2** | **Minimal metadata**: Server learns only fields listed in `METADATA.md`. | M2 | Schema audit test (`cargo test -p tn-server schema_audit`) asserting every SQL column matches `METADATA.md`. | **Verified (M2)** |
| **C3** | **History integrity**: Server cannot modify, delete, reorder, or inject operations without client detecting it. | M3 | Adversarial suite scenarios S1, S2, S3, S4, S5, S6 (`tn-adversary`). | **Verified (M3)** |
| **C4** | **No split view**: Server cannot show different histories to different devices or observers without detection. | M3, M4 | Scenarios S7, S8, S9; witness cosignature verification; device gossip simulation test. | **Verified (M4)** |
| **C5** | **Accountable promises**: Accepted op returns signed receipt with merge deadline; missing inclusion is cryptographic proof of misbehavior. | M3 | Scenario S10 (`ErrMergeDeadlineMissed`), Scenario S11 (`ErrEpochOmission`), evidence bundle export/import test. | **Verified (M3)** |
| **C6** | **Time evidence**: Checkpoints anchored to Bitcoin through OpenTimestamps and verified offline. | M4 | `tn anchor verify` offline proof validation test against mock & real calendar headers. | **Verified (M4)** |
| **C7** | **Release integrity**: Every release binary is reproducible, signed, and recorded in a log the client can check. | M4 | Two-builder byte-for-byte SHA-256 comparison CI job; `tn self-verify` test. | **Verified (M4)** |
| **C8** | **Post-quantum posture**: No long-term confidentiality or authenticity depends only on classical public-key cryptography. | M1, M5 | `CRYPTO.md` audit, NIST ACVP / FIPS 204 KATs for ML-DSA-65 and ML-KEM-768, X-Wing hybrid KEM test vectors. | **Verified (M5)** |
| **C9** | **Operator-independent recovery**: User can restore everything from Recovery Key alone; operator can never restore it for them. | M1, M2 | Recovery test: wipe data directory, execute `tn recovery restore`, assert restored history hash equals pre-wipe. | **Verified (M2)** |
| **C10**| **Third-party auditability**: Outsider can verify C3 to C7 with documented tools and no operator cooperation. | M4, M6 | `tn-monitor` end-to-end audit run against live test server; `VERIFICATION.md` compliance run; desktop verification panel & one-click evidence bundle export (`.tnevidence`). | **Verified (M6)** |

---

## 2. Adversarial Suite Matrix (Scenarios S1–S17)

Every scenario is implemented in `tn-adversary` and asserts three conditions:
1. Exact typed error is returned (`TnError::*`).
2. Previously verified client state remains unchanged.
3. No panic occurs.

| Scenario ID | Attack Description | Required Error | Target Claim | Test Implementation |
|-------------|--------------------|----------------|--------------|---------------------|
| **S1** | Modify ciphertext of a stored op | `ErrCiphertextTampered` | C1, C3 | `tn-adversary::scenarios::s01_tampered_ciphertext` |
| **S2** | Drop an op from a fetch response | `ErrHistoryGap` | C3 | `tn-adversary::scenarios::s02_dropped_op` |
| **S3** | Reorder ops in sequence | `ErrOrderViolation` | C3 | `tn-adversary::scenarios::s03_reordered_ops` |
| **S4** | Inject forged op with bad signature | `ErrBadSignature` | C3 | `tn-adversary::scenarios::s04_forged_signature` |
| **S5** | Inject op from revoked device | `ErrRevokedDevice` | C3 | `tn-adversary::scenarios::s05_revoked_device` |
| **S6** | Roll back by serving older account head | `ErrRollback` | C3 | `tn-adversary::scenarios::s06_head_rollback` |
| **S7** | Fork: show different histories to two devices | `ErrSplitView` | C4 | `tn-adversary::scenarios::s07_fork_split_view` |
| **S8** | Checkpoint with $< k$ witness cosignatures | `ErrWitnessPolicy` | C4 | `tn-adversary::scenarios::s08_insufficient_witnesses`|
| **S9** | Replay old cosigned checkpoint | `ErrRollback` | C4 | `tn-adversary::scenarios::s09_replayed_checkpoint` |
| **S10**| Op accepted & receipted, never included by deadline | `ErrMergeDeadlineMissed` | C5 | `tn-adversary::scenarios::s10_missed_merge_deadline`|
| **S11**| Omit account leaf from epoch tree | `ErrEpochOmission` | C5 | `tn-adversary::scenarios::s11_epoch_leaf_omission` |
| **S12**| Publish two different roots for same epoch | `ErrEquivocation` | C3, C5 | `tn-adversary::scenarios::s12_epoch_equivocation` |
| **S13**| Checkpoint fetch fails (must not use default root)| `ErrUnavailable` | C3 | `tn-adversary::scenarios::s13_fetch_failure_no_fallback`|
| **S14**| Proof verifies against root different from checkpoint | `ErrRootMismatch` | C3 | `tn-adversary::scenarios::s14_proof_root_mismatch` |
| **S15**| Malformed, oversized, or non-canonical CBOR | `ErrDecode` | C3 | `tn-adversary::scenarios::s15_non_canonical_cbor` |
| **S16**| Protocol version downgrade | `ErrUnsupportedVersion` | C3 | `tn-adversary::scenarios::s16_version_downgrade` |
| **S17**| Server signing key changes with no log entry | `ErrUnloggedKeyChange` | C4 | `tn-adversary::scenarios::s17_unlogged_key_rotation`|
