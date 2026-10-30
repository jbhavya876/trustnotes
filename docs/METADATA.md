# TrustNotes Metadata Register (METADATA.md)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Purpose & Authority

This document defines the **exhaustive registry of server-visible fields** in TrustNotes. Under Claim **C2 (Minimal Metadata)**, the server is prohibited from observing or inferring any attribute of the user's data beyond what is strictly necessary to sequence operations, prevent abuse, and enforce transparency.

A permanent CI test (`just doc-lint` / `cargo test -p tn-server schema_audit`) inspects the database migrations and runtime schemas:
> **The build fails immediately if any database column, header, or wire field exists on the server that is not explicitly registered and justified in this document.**

---

## 2. Server-Visible Relational Schema

### 2.1 Table: `accounts`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `account_id` | `BYTEA (32 B)` | 32-byte account identifier ($SHA-256(\text{"tn/v1/account-id"} \mathbin{\Vert} \text{AIK-Ed} \mathbin{\Vert} \text{AIK-PQ})$). | Primary key; routing ops and checking authorization. |
| `aik_pub_bundle` | `BYTEA` | Public keys for classical Ed25519 and post-quantum ML-DSA-65 identity. | Verifying root certificates, device additions, and key transitions. |
| `created_bucket` | `INTEGER` | Time of account creation quantized to 1-hour epochs. | Anti-abuse and retention policy; hourly quantization prevents fine-grained temporal tracking. |

### 2.2 Table: `devices`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `device_id` | `BYTEA (32 B)` | Device identifier ($SHA-256(\text{DSK-Ed} \mathbin{\Vert} \text{DSK-PQ})$). | Routing ops to device lanes and enforcing lane sequence numbers. |
| `account_id` | `BYTEA (32 B)` | Owning account. | Foreign key to `accounts`. |
| `cert` | `BYTEA` | Signed device certificate issued by account AIK. | Cryptographic proof that this device was enrolled by an authorized device. |
| `revoked_at_index` | `BIGINT (Nullable)` | Account tree index at which this device was revoked (null if active). | Enforcing rejection of ops submitted by revoked devices (Scenario S5). |

### 2.3 Table: `ops`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `account_id` | `BYTEA (32 B)` | Account to which the operation belongs. | Indexing ops by account. |
| `idx` | `BIGINT` | Global position of this op in the account's Merkle tree (0, 1, 2, ...). | Total ordering of mutations within the account. |
| `op_id` | `BYTEA (32 B)` | Cryptographic digest of the `OpHeader` (covers `ct_hash`). | Leaf content for RFC 9162 Merkle tree; unique operation identity. |
| `device_id` | `BYTEA (32 B)` | Authoring device for this op. | Verifying lane continuity (`lane_seq`, `lane_prev`). |
| `ct_hash` | `BYTEA (32 B)` | SHA-256 digest of the encrypted payload (`ct`). | Cryptographic verification of payload integrity; permits crypto-shredding. |
| `ct_len_bucket` | `INTEGER` | Coarse size bucket of ciphertext (256, 512, 1024, 2048, 4096, or Padme). | Capacity planning without leaking exact plaintext character counts. |
| `op_bytes` | `BYTEA` | Canonical CBOR serialization of the complete `Op` envelope. | Serving ops to syncing clients; contains ciphertext and signatures. |
| `received_epoch` | `BIGINT` | Epoch number during which the sequencer accepted this op. | Associating op with its epoch commitment. |

### 2.4 Table: `account_heads`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `account_id` | `BYTEA (32 B)` | Account identifier. | Primary key. |
| `size` | `BIGINT` | Total number of ops currently committed in this account tree. | Fast head queries and consistency proof generation. |
| `root` | `BYTEA (32 B)` | RFC 9162 Merkle tree root hash of the account history. | Generating inclusion proofs and epoch tree leaves. |
| `updated_epoch`| `BIGINT` | Epoch number of the last mutation. | Selecting accounts for inclusion in the current epoch tree. |

### 2.5 Table: `epochs`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `epoch_num` | `BIGINT` | Monotonically increasing epoch sequence number (0, 1, 2, ...). | Global ordering of commitment intervals (default 60s). |
| `root` | `BYTEA (32 B)` | Merkle root of the epoch tree built over all accounts changed this epoch. | Leaf $i$ of the global append-only transparency log. |
| `published_at`| `BIGINT` | Unix timestamp (milliseconds) when epoch was signed and published. | Audit timestamp for monitors and witnesses. |

### 2.6 Table: `receipts_issued`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `account_id` | `BYTEA (32 B)` | Account identifier. | Lookup by account. |
| `op_id` | `BYTEA (32 B)` | Unique op identifier. | Binds promise to exact op. |
| `mmd_epoch` | `BIGINT` | Maximum Merge Delay epoch (default `received_epoch + 10`). | Proving server committed to publish by this epoch. |

### 2.7 Table: `nonces`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `device_id` | `BYTEA (32 B)` | Requesting device. | Scoping anti-replay cache. |
| `nonce` | `BYTEA (16 B)` | 16-byte random single-use request nonce. | Anti-replay enforcement; TTL = 5 minutes. |
| `expires_at` | `BIGINT` | Expiration timestamp. | Expired nonces purged automatically. |

### 2.8 Table: `invites`

| Column | Type | What the Server Learns | Justification |
|--------|------|------------------------|---------------|
| `token_hash` | `BYTEA (32 B)` | SHA-256 hash of registration token. | Sybil resistance during alpha/beta onboarding. |
| `used_at` | `BIGINT (Nullable)`| Consumption timestamp. | Single-use invite token enforcement. |

---

## 3. Fields Deliberately Absent from Server

The server possesses **zero visibility** into the following content attributes:
- Note Titles
- Note Markdown Bodies
- Note Tags
- Notebook / Folder Names
- Creation / Modification Timestamps of Notes (inside payload)
- Attachment Filenames, Types, or Payloads
- Plaintext Note Keys (NK) or Vault Keys (VK)
- Object semantic links or relationships (`object_id` is a random 128-bit value)

---

## 4. Ephemeral & Network Metadata

| Data | Retention Period | Storage Location | Treatment |
|------|------------------|------------------|-----------|
| IP Address | Max 24 hours | In-memory Redis/Hashmap | Salted HMAC (`HMAC-SHA-256(IP, DailySalt)`); salt rotates every 24 hours and is deleted. Never written to disk or logs. |
| Request Timestamps | Max 5 minutes | Memory nonce cache | Used exclusively for clock-skew bounds ($\pm 60\text{s}$). |
| TLS Handshake Data | Ephemeral | OS socket buffer | Terminated in-process via rustls; session tickets not tracked. |
