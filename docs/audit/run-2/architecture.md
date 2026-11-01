# TrustNotes Architecture & Threat Boundary Analysis (Run 2 — RC1)

## 1. System Topology & Trust Boundaries

TrustNotes partitions trust across four distinct physical and logical domains:

```text
┌────────────────────────────────────────────────────────┐
│               Client Trust Domain                      │
│                                                        │
│  [Desktop UI (127.0.0.1)] ◄──(Strict CSP / Localhost)──┤
│           │                                            │
│  [Embedded Server] ──(In-memory / Loopback)──┐         │
│           │                                  │         │
│     [tn-core / Vault]                        ▼         │
│  ├── SQLite (Per-column AEAD)       [AI Provider]      │
│  ├── NoteKey / Attachment Key       (Disabled Default; │
│  └── Inverted Search Index           Egress Blocked)   │
└──────────────────────────────────────────────┬─────────┘
                                               │
                   TLS 1.3 / X-TN-* Asymmetric │ Authenticated
                                               ▼
┌────────────────────────────────────────────────────────┐
│               Server Sequencer (Untrusted)             │
│                                                        │
│  - Merkle Tree Log & C2SP Tiles                        │
│  - Quantized Timestamps (1-hour bins)                  │
│  - Padded Ciphertext Buckets (64 KiB)                  │
│  - Signed Checkpoint Emission                          │
└───────────────────────┬────────────────────────────────┘
                        │
       Consistency Proof│ + Checkpoint
                        ▼
┌────────────────────────────────────────────────────────┐
│            Witness Quorum Domain (k-of-n)              │
│                                                        │
│  [Witness 1]        [Witness 2]        [Witness 3]     │
│  (Independent)      (Independent)      (Independent)   │
│                                                        │
│  Invariants Enforced: Monotonicity, Non-Equivocation   │
└────────────────────────────────────────────────────────┘
```

## 2. Security Boundaries

1. **Client Storage Boundary**: Sensitive note fields are encrypted at rest under `LocalStorageKey` derived via Argon2id (m=64 MiB, t=3, p=4) with random salt. Plaintext never touches disk.
2. **Untrusted Server Boundary**: The server is treated as an active Byzantine adversary. It cannot decrypt notes (XChaCha20-Poly1305 under client keys), forge ops (hybrid Ed25519+ML-DSA client signatures), or equivocate history (witness quorum + consistency proofs).
3. **AI Security Boundary**: Default `DisabledAiProvider` blocks all AI calls. If enabled, only loopback (`127.0.0.1`) addresses are permitted, affirmative per-call user consent tokens are required, and network egress is intercepted by `EgressAllowList`.
4. **Desktop UI Boundary**: Zero external JavaScript or CSS. Strict Content Security Policy prohibits remote origins, `eval`, inline scripts, and frame embedding.
