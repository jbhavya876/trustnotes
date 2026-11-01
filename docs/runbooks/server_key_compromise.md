# Incident Response Runbook: Server Signing Key Compromise
**Document**: `docs/runbooks/server_key_compromise.md`  
**Severity**: High (Transparency Log Integrity Impacted)  
**Target Entity**: TrustNotes Log Publisher / Sequencer  

---

## 1. Threat Description & Blast Radius
- **Scenario**: An adversary gains unauthorized access to the Server's Ed25519 and ML-DSA-65 private keys (`LABEL_SIG_RECEIPT` / `LABEL_SIG_CHECKPOINT`).
- **Blast Radius**:
  - The attacker **CANNOT** read note plaintexts, titles, or attachments (Claim C1: end-to-end zero-knowledge AEAD under client keys).
  - The attacker **CANNOT** forge account operations (device operations require device keys).
  - The attacker **COULD** attempt to publish an equivocating checkpoint or omit submitted operations.
  - **Mitigation Invariant**: Under ADR-0001, clients will **NOT** accept any checkpoint signed by the compromised server unless it also carries at least $K$ valid cosignatures from pinned, uncompromised witnesses! If the server equivocates, witnesses detect the consistency failure and refuse to cosign.

---

## 2. Containment & Remediation Procedure

### Phase 1: Revocation & Alerting
1. Issue an emergency out-of-band security advisory alerting all clients and monitors.
2. Publish the SHA-256 fingerprint of the compromised server key to the public transparency monitor channels.
3. Update the global monitor fleet (`tn-monitor`) with an explicit revocation directive for the compromised key ID:
   ```bash
   tn-monitor update-revocations --server-key-revoked <KEY_FINGERPRINT>
   ```

### Phase 2: Key Replacement & Checkpoint Transition
1. Provision a new hybrid keypair for the server sequencer using a hardware security module (HSM) or secure enclave:
   ```bash
   tn-server init-keys --output /secure/server_keys.cbor --force-new
   ```
2. Generate a transition checkpoint that binds the previous log root to the new server key, signed by both the retired and new keys (or certified out-of-band by witness quorum).
3. Distribute the new Server Public Key (`VerifyingKeys`) via:
   - Dynamic DNS / HTTPS signed metadata document (`/.well-known/trustnotes-server.json`).
   - Witness registry consensus update.

### Phase 3: Client Recovery
1. The TrustNotes client verifies the transition checkpoint:
   - Verifies the consistency proof from the last known checkpoint to the transition checkpoint.
   - Verifies that $\ge K$ pinned witnesses have cosigned the transition.
2. The client updates its pinned server verifying key and resumes normal operation.
