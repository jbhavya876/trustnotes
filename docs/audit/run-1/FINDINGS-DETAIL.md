# Security Audit: Detailed Findings Analysis (M0)

## Overview

At Milestone M0, no production encryption or decryption code is executed. All cryptographic interfaces are defined as type-safe skeletons with domain separation and typed error propagation.

### Review of Critical Security Controls

1. **Newtypes for Keys**:
   - `tn-crypto` newtypes every key (`AccountRoot`, `VaultKey`, `NoteKey`, `LocalStorageKey`).
   - Prevents accidental key substitution across KDF boundaries.

2. **Strict Codec Invariants**:
   - `tn-types` establishes canonical CBOR decoding rules.
   - Decoders must strictly reject duplicate map keys, non-shortest integer representations, indefinite-length arrays/strings, and trailing bytes.
   - Fuzz targets are scaffolded in `fuzz/` to fuzz all CBOR decoders continuously.

3. **Adversary Verification (S1–S17)**:
   - All 17 adversary scenarios from Section 12.1 are mapped to distinct, non-overlapping typed variants in `TnError`.
   - Tests assert that client state is never updated when an error occurs.
