# ADR-0002: Enrolled Devices Hold Account Root and Vault Key (Trade-off T3)

- **Status**: Accepted (Human sign-off granted in M0 Plan approval)
- **Date**: 2026-10-31
- **Deciders**: Bhavya (AlterBlock), AI Staff Engineer
- **Trade-off ID**: T3

---

## Context

TrustNotes supports multi-device synchronization without trusting the server with cryptographic keys. When a user introduces a second or third device (e.g. laptop, desktop), the new device must receive the necessary key material to read past notes and issue authenticated operations.

We considered two primary architectural approaches for key delegation:
1. **Option A (Every Enrolled Device Holds Account Root & Vault Key)**:
   Every enrolled device holds Account Root (AR) and Vault Key (VK) in its Local Storage Key (LSK)-protected store. Any currently active device can authorize and enroll a new device by issuing a device certificate signed by AIK and transmitting AR/VK over an HPKE-encrypted channel.
2. **Option B (Offline-Only Identity Root)**:
   AIK is kept exclusively on an offline paper backup or dedicated hardware security token. Enrolled devices possess only device-specific signing keys (DSK) and an encrypted cache of current note keys, requiring the offline root key every time a new device is added.

---

## Decision

We adopt **Option A (Default)**: Every enrolled device holds AR and VK inside its LSK-protected local vault.

### Rationale
- **Usability**: Users can enroll a new laptop from an existing desktop using a 6-word Short Authentication String (SAS) QR flow without locating their 24-word physical recovery sheet.
- **Recovery**: If a device is destroyed, any remaining active device can re-seed a replacement. If all devices are lost, the user restores AR directly from the 24-word Recovery Key.

---

## Security Consequences & Mitigations

- **Risk**: A stolen, unlocked physical device gives an attacker access to AR and VK, allowing them to sign device certificates or read past notes.
- **Mitigation 1 (At-Rest Protection)**: AR and VK are stored in SQLite encrypted with per-column AEAD under LSK stored in the OS Keystore (Keyring), with optional Argon2id passphrase wrapping.
- **Mitigation 2 (Device Revocation - M2)**: Users can revoke a lost device from any remaining device (`device-revoke` op). Ops submitted by the revoked device after its revocation index are rejected by the server and ignored by clients.
- **Mitigation 3 (Full Key Rotation - M5)**: In the event of confirmed compromise, the user executes a full key rotation: generating $RK'$, deriving $AR', AIK', VK'$, cross-signing a transition op, and re-wrapping Note Keys lazily.
- **Transparency**: Stolen devices cannot alter history retrospectively without triggering split-view or history-gap errors across other enrolled devices and public witnesses.
