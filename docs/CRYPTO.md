# TrustNotes Cryptographic Specification

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Cryptographic Primitives

TrustNotes strictly adheres to published standards and vetted, audited implementations. No novel composition of primitives is permitted without an approved Architecture Decision Record (ADR).

| Purpose | Primitive | Standard | Notes |
|---------|-----------|----------|-------|
| Content AEAD | XChaCha20-Poly1305 | RFC 8439 / XChaCha draft | 256-bit key, 192-bit random nonce. Nonce prepended to ciphertext. |
| Hash Function | SHA-256 | FIPS 180-4 | Merkle trees, op_ids, checkpoint and leaf hashes. |
| Key Derivation (KDF) | HKDF-SHA-256 | RFC 5869 | Single info label per usage. Salt = empty or parent key. |
| Message Authentication | HMAC-SHA-256 | RFC 2104 | Pseudonymous labels and rate-limit tracking keys only. |
| Password KDF | Argon2id | RFC 9106 | Local key wrapping when passphrase mode enabled. Desktop default: $m=256\text{ MiB}, t=3, p=1$. Floor: $m=64\text{ MiB}, t=3$. |
| Classical Signature | Ed25519 | RFC 8032 | Pure Ed25519 over context-prefixed canonical bytes. |
| Post-Quantum Signature | ML-DSA-65 | FIPS 204 | Domain separation via native `ctx` parameter. |
| Hybrid Signature Rule | Both must verify (AND) | Custom rule | Pair $(S_{ed}, S_{pq})$. Failure of either rejects immediately. Never OR. |
| Key Encapsulation (KEM) | X-Wing (X25519 + ML-KEM-768) | draft-connolly-cfrg-xwing-02, RFC 9180 | Hybrid KEM inside HPKE for device enrollment and sharing. |
| Network Transport | TLS 1.3 only | RFC 8446 | rustls backend. Hybrid X25519MLKEM768 enabled where supported. No TLS 1.2 fallback. |
| Merkle Tree | RFC 9162 Hash Tree | RFC 9162 §2.1 | Leaf prefix `0x00`, interior node prefix `0x01`. Compatible with C2SP tlog ecosystem. |
| Checkpoints & Logs | C2SP Signed Note | c2sp.org/tlog-checkpoint | `tlog-checkpoint`, `tlog-cosignature`, `tlog-witness`, `tlog-tiles`. |
| Deterministic Codec | Canonical CBOR | RFC 8949 §4.2 | Strict decode: reject duplicate keys, indefinite lengths, non-shortest ints, trailing bytes. |
| Randomness | OS CSPRNG | Operating System | Via `getrandom` crate. No userland PRNG for keys or nonces. |

---

## 2. Key Hierarchy

```
Recovery Key RK (256-bit entropy, displayed as 24 BIP-39 words)
  |
  +---> HKDF-SHA-256(RK, info="tn/v1/account-root") -> Account Root AR (32 bytes)
          |
          +---> HKDF(AR, "tn/v1/identity-ed25519") -> Account Identity Key (AIK-Ed, 32B seed)
          +---> HKDF(AR, "tn/v1/identity-mldsa65") -> Account Identity Key (AIK-PQ, 32B seed)
          +---> HKDF(AR, "tn/v1/vault-key")        -> Vault Key VK (32 bytes)
          |
          account_id = SHA-256("tn/v1/account-id" || AIK-Ed pubkey || AIK-PQ pubkey)

Per Enrolled Device (Generated on device, private keys never leave local device):
  - Device Signing Key DSK: (Ed25519, ML-DSA-65) keypair
  - Device Transport Key DTK: X-Wing keypair
  - Local Storage Key LSK: 32 random bytes stored in OS Keystore (Keyring)
      (Optionally wrapped by Argon2id in passphrase mode)

Per Note:
  - Note Key NK: 32 random bytes
  - Wrapped under Vault Key (VK) with XChaCha20-Poly1305:
      AAD = object_id || "tn/v1/nk-wrap"
```

*Trade-off T3 (ADR-0002)*: Every enrolled device holds AR and VK in its LSK-protected store so any device can enroll new devices. If a device is compromised, device revocation (kind 4) or full recovery key rotation (kind 5) is required.

---

## 3. Context Label Registry (Domain Separation)

All context labels are ASCII, versioned with prefix `tn/v1/`, and dedicated to a single invariant:

| Context Label | Primitive | Input / Role | Security Invariant |
|---------------|-----------|--------------|---------------------|
| `tn/v1/account-root` | HKDF-SHA-256 | RK $\to$ AR derivation | Never used for identity or encryption keys |
| `tn/v1/identity-ed25519` | HKDF-SHA-256 | AR $\to$ AIK-Ed seed | Independent classical identity root |
| `tn/v1/identity-mldsa65` | HKDF-SHA-256 | AR $\to$ AIK-PQ seed | Independent post-quantum identity root |
| `tn/v1/vault-key` | HKDF-SHA-256 | AR $\to$ VK | Master key for wrapping Note Keys |
| `tn/v1/account-id` | SHA-256 | Pubkey bundle prefix | Binds account_id to hybrid identity keys |
| `tn/v1/nk-wrap` | XChaCha20-Poly1305 | AAD for NK wrapping | Binds wrapped note key to object_id |
| `tn/v1/op-id` | SHA-256 | OpHeader hash prefix | Computes unique op identifier covering ct_hash |
| `tn/v1/sig/op` | Ed25519 / ML-DSA-65 | Signature domain label | Authorizes mutations submitted by device |
| `tn/v1/aead/op` | XChaCha20-Poly1305 | AAD for note payload | Authenticates op metadata with payload |
| `tn/v1/epoch-leaf` | SHA-256 | Leaf hash prefix in epoch tree | Prevents account enumeration in monitors |
| `tn/v1/receipt/sig` | Ed25519 / ML-DSA-65 | Server receipt signature | Binds server to merge deadline promise |
| `tn/v1/device/cert` | Ed25519 / ML-DSA-65 | Device certificate signature | Links device public keys to account AIK |
| `tn/v1/device/enrollment` | HPKE (X-Wing) | Info string for AR delivery | Encrypts AR to new device's DTK |
| `tn/v1/gossip/sig` | Ed25519 / ML-DSA-65 | Device gossip checkpoint | Prevents forged gossip equivocation |
| `tn/v1/evidence/bundle` | Canonical CBOR | Misbehavior bundle format | Verifiable by third-party monitors |

A permanent CI test (`just doc-lint`) scans all crate source files for string literals matching `tn/v1/` and fails if any literal is absent from this table or used across conflicting call sites.

---

## 4. Padding Specification

To minimize traffic analysis and metadata leakage (A1, A3), plaintexts are padded before AEAD encryption:
1. Append byte `0x80` followed by `0x00` bytes (ISO/IEC 7816-4).
2. Pad to fixed bucket boundaries:
   - $\le 256\text{ bytes} \to 256\text{ bytes}$
   - $\le 512\text{ bytes} \to 512\text{ bytes}$
   - $\le 1024\text{ bytes} \to 1024\text{ bytes}$
   - $\le 2048\text{ bytes} \to 2048\text{ bytes}$
   - $\le 4096\text{ bytes} \to 4096\text{ bytes}$
3. For plaintexts $> 4096\text{ bytes}$, compute bucket using **Padme** (PURB):
   $$\text{target} = \text{padme\_bucket}(\text{len})$$
A property test in `tn-crypto` asserts that ciphertext lengths across random plaintext distributions fall strictly within this bounded set.

---

## 5. Rules for Cryptographic Code

1. **Newtypes for Keys**: Every key is wrapped in a distinct type (`AccountRoot`, `VaultKey`, `NoteKey`, `LocalStorageKey`). Raw `[u8; 32]` never crosses module boundaries.
2. **Encapsulated Nonce Generation**: Callers cannot pass nonces to `aead::seal`. Nonces are generated using the OS CSPRNG directly inside the wrapper.
3. **Secrets Hygiene**: Secret types implement `zeroize::ZeroizeOnDrop` and `secrecy::Secret`. No `Debug` formatting prints secret contents; `Clone` is forbidden unless explicitly required.
4. **Strict Constant-Time Comparisons**: All comparisons of tags, MACs, signatures, or hashes use `subtle::ConstantTimeEq`.
5. **No Userland PRNG**: Keys and nonces are sourced exclusively via `getrandom`.
