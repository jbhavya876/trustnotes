# TrustNotes Test Data & Canonical Wire Samples

This directory contains reference sample instances for every CDDL type defined in `docs/cddl/`.

## Notice: Test Only Fixtures

All keys, signatures, and IDs in these samples are test fixtures generated with **TEST ONLY** seeds. They must never be deployed in any production environment.

## Sample Inventory

| File | Type | Description |
|------|------|-------------|
| `op_sample.json` | `Op` | Note creation op (kind 1: `put`) |
| `receipt_sample.json` | `Receipt` | Sequencer receipt with MMD promise |
| `checkpoint_sample.json` | `CheckpointResponse` | Witnessed checkpoint with 2-of-3 cosignatures |
| `evidence_bundle_sample.json` | `EvidenceBundle` | Missed merge deadline proof bundle |
| `device_certificate_sample.json` | `DeviceCertificate` | AIK-signed device authorization certificate |
| `enrollment_package_sample.json` | `EnrollmentBlob` | HPKE-encrypted device enrollment package |
