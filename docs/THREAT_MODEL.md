# TrustNotes Threat Model

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. System Overview & Trust Boundaries

TrustNotes is an end-to-end encrypted notes system where the server is explicitly untrusted.

```
       +-------------------------------------------------------------+
       |                        USER DEVICE                          |
       |                                                             |
       |  +--------------------+             +--------------------+  |
       |  | Unlocked Client UI |             | In-Memory Notes DB |  |
       |  +--------------------+             +--------------------+  |
       |            |                                   |            |
       |            +=================+=================+            |
       |                              |                              |
       |             [TRUST BOUNDARY 1: Local Device Store]          |
       |                              |                              |
       |                   +---------------------+                   |
       |                   | SQLite Encrypted    |                   |
       |                   | (Per-column AEAD)   |                   |
       |                   +---------------------+                   |
       +------------------------------|------------------------------+
                                      | TLS 1.3 (Signed Requests: X-TN-*)
       ===============================|===============================
       [TRUST BOUNDARY 2: Network / Untrusted Transport]
       ===============================|===============================
                                      |
       +------------------------------v------------------------------+
       |                       UNTRUSTED SERVER                      |
       |                                                             |
       |   +-----------------------+     +-----------------------+   |
       |   | Postgres Relational   |     | Sequencer & Epoch     |   |
       |   | (Ciphertext + Metadata)|     | Publisher             |   |
       |   +-----------------------+     +-----------------------+   |
       +------------------------------|------------------------------+
                                      | Checkpoints + Consistency Proofs
       ===============================|===============================
       [TRUST BOUNDARY 3: Transparency Log Ecosystem]
       ===============================|===============================
          |                           |                           |
          v                           v                           v
   +---------------+           +---------------+           +---------------+
   | Witness Node 1|           | Witness Node 2|           | Witness Node 3|
   | (Independent) |           | (Independent) |           | (Independent) |
   +---------------+           +---------------+           +---------------+
          |                           |                           |
          +===========================+===========================+
                                      | Cosignatures (k-of-n)
                                      v
                             +-----------------+
                             | Third-Party     |
                             | Monitors / OTP  |
                             +-----------------+
```

### Trust Boundary Rules
1. **Local Boundary (Client)**: Note plaintext exists strictly in process memory while the vault is unlocked. On-disk SQLite stores every sensitive field as an XChaCha20-Poly1305 ciphertext encrypted under the Local Storage Key (LSK).
2. **Network Boundary**: All client-server traffic is encrypted under TLS 1.3. Mutating and private requests carry hybrid request signatures (`X-TN-Sig`) with anti-replay nonces and timestamps.
3. **Server Boundary**: The server stores ciphertext, logs, and metadata. It has **no access to any encryption or identity keys**. It cannot forge ops, modify notes, or alter sequencing without violating Merkle consistency.
4. **Transparency Boundary**: The server must publish commitments to independent witnesses. A malicious server cannot show different histories (forks) to different devices without being caught by witness cosignatures and peer device gossip.

---

## 2. Adversary Catalogue (A1–A9)

| Adversary | Description & Capability | Primary Defense | Residual Risk | Touches Claims | Scenarios |
|-----------|--------------------------|-----------------|---------------|----------------|-----------|
| **A1** Passive Network Observer | Records network traffic, packet timings, and volume. | TLS 1.3 with hybrid post-quantum key exchange (X25519MLKEM768); E2EE inside payload; padded ciphertext buckets. | IP address, packet timing, approximate payload size buckets. | C1, C2, C8 | — |
| **A2** Active Network Attacker | Man-in-the-middle, replay attacks, protocol downgrade, injection. | Strict TLS certificate validation; hybrid request signatures (`X-TN-Sig`); single-use cached nonces; 60s max timestamp skew; strict protocol version check. | Temporary denial of service (availability). | C1, C3 | S4, S15, S16 |
| **A3** Honest-but-Curious Operator | Reads server databases, queries, filesystem blobs, memory dumps, and backups. | End-to-end encryption under Note Keys; Note Keys wrapped under Vault Key; minimal server metadata (`METADATA.md`); ciphertext size padding. | Operator observes metadata explicitly documented in `METADATA.md` (account creation bucket, lane seq numbers, update epoch). | C1, C2 | S1 |
| **A4** Malicious Operator | Rewrites ops, drops ops, reorders history, forks state, serves stale data, replays old state. | Client verification pipeline (RFC 9162 Merkle tree, lane hash chains, signed receipts with merge deadlines, witnessed epoch trees, device gossip). | Withholding data is detected, not prevented. Detection latency bounded by merge deadline and gossip interval. | C3, C4, C5 | S1, S2, S3, S4, S5, S6, S7, S10, S11, S12 |
| **A5** Full Server Compromise | Attacker obtains full host control, database access, and server signing keys. | Server never holds user private keys or note keys. Server-key rotation is a logged event in the global transparency log. Witnesses reject split histories. | Window before detection bounded by witness checking frequency. | C1, C3, C4, C5 | S12, S17 |
| **A6** Stolen User Device | Attacker has physical/disk access to user hardware. | At-rest per-column AEAD encryption under LSK stored in OS keystore; optional passphrase-derived master key via Argon2id; device revocation op. | If device was left unlocked, attacker possesses full read access to local vault memory. | C1, C9 | S5 |
| **A7** Malicious Witness Minority | A compromised or colluding witness signs invalid or equivocal checkpoints. | $k$-of-$n$ threshold policy (default 2-of-3); witnesses independently operated by separate legal entities. | Collusion of $k$ or more witnesses could sign a split view. Mitigated by device gossip and public monitors (`tn-monitor`). | C4, C10 | S8, S9 |
| **A8** Supply Chain Attack | Compromised upstream dependency, malicious build script, or poisoned release artifact. | `#![forbid(unsafe_code)]`; strictly vetted dependencies; `cargo deny`, `cargo audit`, `cargo vet`; pinned toolchains; reproducible containerized builds verified by two independent builders; release transparency log. | First-install bootstrap trust. | C7 | — |
| **A9** Future Quantum Adversary | Harvests ciphertexts today, decrypts or forges signatures with cryptographically relevant quantum computer tomorrow. | 256-bit symmetric cipher keys (unaffected by Shor's); hybrid post-quantum signatures (Ed25519 + ML-DSA-65) with mandatory AND rule; hybrid key encapsulation (X-Wing: X25519 + ML-KEM-768). | Young PQ implementation bugs; hedged by hybrid classical+PQ design. | C8 | — |

---

## 3. Two Classic Verifier Bugs (Regression Protections)

The client verification engine explicitly prevents two common verifier implementation flaws:

1. **Silent Fallback to Default/Unverified Root (Scenario S13)**:
   - *Vulnerability*: If fetching a checkpoint fails, an insecure client might substitute a hardcoded, cached, or null root, accepting unverified ops.
   - *Enforcement*: Any checkpoint fetch failure aborts the sync loop with `ErrUnavailable`. Previously verified local state remains completely unchanged.
2. **Proof Verified Against Discarded Root (Scenario S14)**:
   - *Vulnerability*: The client computes a root from an inclusion/consistency proof but fails to assert that this computed root matches the witnessed checkpoint root.
   - *Enforcement*: The proof verification function takes the witnessed checkpoint root as a mandatory parameter and asserts constant-time equality. Mismatch immediately emits `ErrRootMismatch`.

---

## 4. Explicit Non-Claims (User-Facing)

To maintain credibility and scientific honesty, TrustNotes explicitly does **not** claim:
1. **Endpoint Security**: If malware, keyloggers, or a hostile operating system compromises the user's client machine, all cryptographic guarantees are defeated.
2. **Guaranteed Availability**: The untrusted server can choose to go offline or withhold data. TrustNotes guarantees that omission is cryptographically detected, not that availability is forcibly guaranteed.
3. **Complete Anonymity & Traffic Analysis Resistance**: IP addresses and synchronization timing are visible to network observers and the operator. Padded size buckets reduce, but do not completely eliminate, side-channel size leakage.
4. **Protection Against Coercion or Key Loss**: Physical coercion, shoulder surfing, screenshots, or accidental loss of the 24-word Recovery Key cannot be defended against by cryptography.
5. **Instant Misbehavior Detection**: Detection latency depends on client sync frequency, device gossip intervals, and the server merge deadline (default 10 epochs / 10 minutes).
