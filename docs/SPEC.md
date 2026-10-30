# TrustNotes Protocol Specification (v1)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Overview & System Model

TrustNotes is an end-to-end encrypted notes system whose server behavior is publicly verifiable: **private by content, transparent by behavior**. Note contents are accessible strictly to the user's enrolled devices. Every mutating operation processed by the untrusted server is committed to in append-only cryptographic data structures:
1. **Per-Account Merkle Tree (RFC 9162)**: Sequences operations belonging to an account.
2. **Epoch Tree**: Batches account commitments each epoch (default 60s) using hashed account leaves.
3. **Global Transparency Log**: An append-only log of epoch roots, signed by the server and cosigned by independent witnesses according to a $k$-of-$n$ policy.

Clients verify that the server neither injects, modifies, drops, reorders, forks, nor rolls back operations.

---

## 2. Operation Format (Op)

The fundamental unit of synchronization and persistence is the `Op`. Every mutation (note creation, note edit, deletion, device enrollment, device revocation, key rotation, crypto-shredding) is expressed as an `Op`.

### 2.1 Wire Representation

```cddl
Op = {
  v: uint,                       ; protocol version, 1
  account_id: bstr .size 32,    ; SHA-256('tn/v1/account-id' || AIK-Ed pub || AIK-PQ pub)
  device_id: bstr .size 32,     ; SHA-256(DSK-Ed pub || DSK-PQ pub)
  lane_seq: uint,               ; per-device monotonically increasing sequence counter, starting at 0
  lane_prev: bstr .size 32 / null, ; op_id of previous op in this device lane (null for lane_seq 0)
  hlc: [uint, uint],            ; hybrid logical clock [wall_time_ms, counter]: advisory only
  kind: uint,                   ; 1 put, 2 delete, 3 device-add, 4 device-revoke, 5 key-rotate, 6 shred
  object_id: bstr .size 16,     ; 128-bit random UUID, opaque to server
  nk_wrap: bstr / null,         ; Note Key encrypted under Vault Key (XChaCha20-Poly1305)
  nonce: bstr .size 24,         ; 192-bit random nonce for content AEAD
  deps: [* bstr .size 32],      ; op_ids this op causally succeeds
  ct: bstr,                     ; ciphertext of padded payload (XChaCha20-Poly1305)
  sig_ed: bstr .size 64,        ; Ed25519 signature over canonical(header) under 'tn/v1/sig/op'
  sig_pq: bstr                  ; ML-DSA-65 signature over canonical(header) with ctx 'tn/v1/sig/op'
}
```

### 2.2 Header and Op ID Derivation

Signatures and the `op_id` bind to the `OpHeader`, which covers `ct_hash` rather than `ct`. This enables **crypto-shredding** (kind 6), allowing the server to safely purge shredded ciphertexts while all signatures, inclusion proofs, and tree positions remain valid:

$$\text{ct\_hash} = \text{SHA-256}(\text{ct})$$

$$\text{header} = \text{canonical\_cbor}(\{ v, \text{account\_id}, \text{device\_id}, \text{lane\_seq}, \text{lane\_prev}, \text{hlc}, \text{kind}, \text{object\_id}, \text{nk\_wrap}, \text{nonce}, \text{deps}, \text{ct\_hash} \})$$

$$\text{op\_id} = \text{SHA-256}(\text{"tn/v1/op-id"} \mathbin{\Vert} \text{header})$$

### 2.3 Op Kinds

| Kind | Name | Semantics |
|------|------|-----------|
| 1 | `put` | Create or update note payload (title, body, tags, notebook). |
| 2 | `delete` | Soft delete; note marked trashed, payload retained reversibly. |
| 3 | `device-add` | Enrolls a new device via certificate cross-signed by Account Identity Key (AIK). |
| 4 | `device-revoke` | Revokes a device. Ops from that device with `lane_seq` beyond revocation point are rejected. |
| 5 | `key-rotate` | Transitions Account Root to AR' with cross-signed transition certificate. |
| 6 | `shred` | Crypto-shredding: client drops Note Key locally and requests server purge `ct`. |

### 2.4 Payload (Inside AEAD Ciphertext)

Decrypted using Note Key (NK) with AEAD Associated Data (AAD):
$$\text{AAD} = \text{canonical\_cbor}(\{ v, \text{account\_id}, \text{device\_id}, \text{lane\_seq}, \text{object\_id}, \text{kind} \})$$
prefixed with context label `tn/v1/aead/op`.

```cddl
Payload = {
  schema_v: uint,
  title: tstr,
  body_md: tstr,
  tags: [* tstr],
  notebook_id: bstr .size 16 / null,
  flags: uint,                  ; bit 0: pinned, bit 1: trashed
  created_at: uint,             ; Unix ms
  updated_at: uint              ; Unix ms
}
```

---

## 3. Server Receipts and Merge Deadlines

When an `Op` is accepted by the server, the sequencer assigns its position in the account tree and issues a hybrid-signed `Receipt`:

```cddl
Receipt = {
  v: uint,
  account_id: bstr .size 32,
  op_id: bstr .size 32,
  index: uint,                  ; 0-based index in the account tree
  account_tree_size_after: uint,
  server_time: uint,            ; Unix ms
  mmd_epoch: uint,              ; Maximum Merge Delay: target epoch for global publication
  sig_ed: bstr .size 64,        ; Server Ed25519 signature
  sig_pq: bstr                  ; Server ML-DSA-65 signature
}
```

Default MMD: **10 epochs** (10 minutes). If an op is not provably included in a witnessed global checkpoint by `mmd_epoch`, the client constructs an **Evidence Bundle** proving server omission.

---

## 4. Transparency Architecture

### 4.1 Three Commitment Tiers

```
[Op 0] [Op 1] ... [Op N]  <- Account Tree leaves (RFC 9162 Merkle tree per account)
          |
     Account Root
          |
   [Epoch Tree Leaf]      <- SHA-256('tn/v1/epoch-leaf' || SHA-256(acc_id) || size || acc_root)
          |
      Epoch Root
          |
   [Global Log Leaf]      <- Append-only RFC 9162 log of all Epoch Roots
          |
   Witnessed Checkpoint   <- Signed by server + >= k independent witness cosignatures
```

1. **Account Tree**: Leaves are `op_id`s in sequencer order. Provides inclusion proofs for ops and consistency proofs between account sizes.
2. **Epoch Tree**: Built every epoch across all accounts modified in that interval. Leaves are hashed:
   $$\text{leaf} = \text{SHA-256}(\text{"tn/v1/epoch-leaf"} \mathbin{\Vert} \text{SHA-256}(\text{account\_id}) \mathbin{\Vert} \text{tree\_size} \mathbin{\Vert} \text{account\_root})$$
   *Privacy Guarantee*: Monitors see only hashed leaves and cannot enumerate account IDs.
3. **Global Log**: Append-only log of epoch roots. Produces checkpoints compatible with C2SP `tlog-checkpoint`.

### 4.2 Witness Protocol (C2SP)

Witnesses run independent instances of `tn-witness`. When presented with a checkpoint proposal $C_{new}$ and consistency proof from the last cosigned checkpoint $C_{prev}$, the witness verifies:
1. Origin matches known log.
2. $N_{new} \ge N_{prev}$.
3. Consistency proof from $C_{prev}$ to $C_{new}$ is cryptographically valid.
4. Timestamp is non-decreasing.

Upon verification, the witness issues a signed note cosignature (`tlog-cosignature`).

---

## 5. Client Verification Pipeline (Fail-Closed)

The client executes this pipeline on every sync. Any failure aborts with a typed error and rolls back to verified state:

1. **Fetch & Verify Checkpoint**:
   - Verify server hybrid signature.
   - Verify at least $k$ distinct pinned witness cosignatures within allowable age.
   - Check consistency against stored checkpoint $C_0$ ($N \ge N_0$). Persist new checkpoint only after all checks pass.
2. **Fetch & Verify Ops**:
   - For each op: verify Ed25519 and ML-DSA-65 signatures.
   - Validate device certificate chain to AIK.
   - Verify lane continuity: `lane_seq = lane_prev.seq + 1`, `lane_prev = prev.op_id`.
   - Verify AEAD authentication on decryption.
3. **Account Tree Verification**:
   - Verify consistency proof from stored account head to new head.
   - Verify leaf positions of fetched ops.
4. **Finality Determination**:
   - Ops older than MMD verified against witnessed global checkpoint $\to$ marked **verified-final**.
   - Younger ops marked **provisional** (highlighted in UI).
5. **On Verification Failure**:
   - Abort sync. Preserve local database intact.
   - Emit typed error (`ErrCiphertextTampered`, `ErrSplitView`, `ErrMergeDeadlineMissed`, etc.).
   - If an accountable promise was broken, export an **Evidence Bundle**.

---

## 6. HTTP API Specification (/v1)

All endpoints consume and return strict deterministic CBOR unless otherwise stated.

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/v1/accounts` | Register account with AIK and initial op | Proof-of-work or invite token |
| `POST` | `/v1/ops` | Submit batch of up to 64 ops with optimistic concurrency | `X-TN-*` hybrid signature |
| `GET` | `/v1/ops?after=&limit=` | Fetch ops with account-tree positions | `X-TN-*` |
| `GET` | `/v1/account/head` | Fetch latest account tree size and root | `X-TN-*` |
| `GET` | `/v1/account/proof/inclusion?index=` | Inclusion proof for op index in account tree | `X-TN-*` |
| `GET` | `/v1/account/proof/consistency?from=&to=` | Consistency proof between account sizes | `X-TN-*` |
| `GET` | `/v1/epoch/{n}/proof` | Inclusion proof of caller's account in epoch $n$ | `X-TN-*` |
| `GET` | `/v1/log/checkpoint` | Latest checkpoint with witness cosignatures | Public |
| `GET` | `/v1/log/tile/{level}/{index}` | RFC 9162 static Merkle tile | Public (cacheable) |
| `GET` | `/v1/log/proof/consistency?from=&to=` | Global log consistency proof | Public |
| `POST` | `/v1/blobs` | Store encrypted opaque blob (enrollment, gossip) | `X-TN-*` |
| `GET` | `/v1/blobs/{id}` | Retrieve encrypted opaque blob | `X-TN-*` |
| `GET` | `/v1/server-info` | Server pubkeys, limits, witness list, protocol version | Public |

### 6.1 Authentication Scheme

Mutating and private endpoints require:
- `X-TN-Device`: 32-byte device identifier (hex).
- `X-TN-Nonce`: 16 random bytes (hex). Nonces cached 5 minutes; duplicates rejected with 401.
- `X-TN-Time`: Unix ms. Skew $> 60\text{s}$ rejected with 401.
- `X-TN-Sig`: Base64-encoded hybrid signature over:
  $$\text{canonical\_cbor}(\{ \text{method}, \text{path}, \text{query}, \text{body\_hash}, \text{nonce}, \text{time}, \text{server\_origin} \})$$
  signed with Device Signing Key (Ed25519 + ML-DSA-65).
