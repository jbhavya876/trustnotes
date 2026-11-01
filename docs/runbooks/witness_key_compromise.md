# Incident Response Runbook: Witness Key Compromise
**Document**: `docs/runbooks/witness_key_compromise.md`  
**Severity**: Medium to Critical (Depending on number of compromised witnesses)  
**Target Entity**: Pinned Cosigning Witness Node  

---

## 1. Threat Description & Threshold Security

- **Scenario 1: Single Witness Compromise ($< K$ witnesses)**
  - In a 2-of-3 witness policy, compromise of 1 witness gives the adversary **ZERO** ability to forge or equivocate checkpoints.
  - A compromised single witness cannot trick clients into accepting a split or rolled-back view because clients require at least 2 distinct pinned witness cosignatures.
- **Scenario 2: Quorum Compromise ($\ge K$ witnesses)**
  - If 2 out of 3 witnesses are compromised concurrently alongside the server key, an attacker could attempt to produce split-view checkpoints for targeted clients.
  - Mitigated by: Third-party auditor monitors (`tn-monitor`) gossiping checkpoints across independent networks, plus Bitcoin OpenTimestamps epoch anchors (Scenario S14).

---

## 2. Containment & Remediation Procedure

### Phase 1: Isolation
1. The operator of the compromised witness node immediately halts the witness daemon:
   ```bash
   systemctl stop tn-witness
   ```
2. Destroy the compromised private key material and secure instance logs for forensic review.

### Phase 2: Quorum Emergency Reconfiguration
1. The log operator and remaining honest witnesses coordinate an updated `WitnessPolicy`.
2. Generate a new witness keypair on hardened infrastructure:
   ```bash
   tn-witness init-keys --output /secure/witness_replacement.key
   ```
3. Issue a policy update transaction:
   - Add the new witness public key ID to `pinned_witnesses`.
   - Remove the compromised witness key ID.
   - Maintain the minimum threshold $K \ge 2$.

### Phase 3: Client Policy Propagation
1. Publish the signed policy transition statement signed by the remaining valid witnesses and server.
2. Clients fetch the policy update during synchronization and verify that the retirement was certified by honest quorum.
