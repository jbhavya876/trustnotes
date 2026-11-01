# TrustNotes Operational Drills
**Document**: `docs/runbooks/drills.md`  
**Scope**: Disaster Recovery, Backup Verification, and Cryptographic Shredding  

---

## 1. Backup-Restore Drill

### Purpose
Validate that a TrustNotes user can fully restore their encrypted vault from:
1. The 24-word BIP-39 recovery phrase (or master root seed), AND
2. The encrypted operation log fetched from an untrusted server or offline SQLite snapshot.

### Step-by-Step Procedure
1. **Simulate Total Local Device Loss**:
   - In a test environment, delete local vault directory:
     ```bash
     rm -rf ~/.trustnotes/vault.db*
     ```
2. **Execute Headless Recovery**:
   - Restore keys and initialize fresh vault using the 24-word recovery phrase:
     ```bash
     tn-cli init-from-phrase --phrase "twenty four word mnemonic phrase ..." --db-path ~/.trustnotes/restored.db
     ```
3. **Synchronize & Replay OpLog**:
   - Query remote server for all account ops:
     ```bash
     tn-cli sync --server https://trustnotes.example.com
     ```
4. **Materialize & Verify Invariants**:
   - Verify that all notes, decrypted titles, markdown bodies, and tags match the pre-drill snapshot.
   - Run cryptographic verification:
     ```bash
     tn-cli verify --all
     ```
   - Assert: All hashes, Merkle proofs, and signatures pass with 0 errors.

---

## 2. Crypto-Shred Data Deletion Drill (Right to Erasure / Panic Wipe)

### Purpose
Ensure that when a user deletes a note or executes an account panic purge:
1. The corresponding symmetric note key (`NoteKey`) is permanently destroyed.
2. Even if ciphertext blocks or raw SQLite pages remain on disk or backups, they are rendered mathematically irrecoverable (Claim C1, SPEC §3.4).

### Step-by-Step Procedure
1. **Note Deletion / Key Shredding**:
   - Execute note deletion via client API or CLI:
     ```bash
     tn-cli delete-note <NOTE_ID> --crypto-shred
     ```
   - Client emits `OpKind::Delete` which overwrites the keyring slot with random noise and removes the key from memory.
2. **Memory & Disk Verification**:
   - Inspect SQLite database file:
     ```bash
     strings ~/.trustnotes/vault.db | grep -F "canary_secret_text"
     # MUST return 0 matches
     ```
   - Attempt key unwrapping:
     - Run `tn-cli read-note <NOTE_ID>`: must return `TnError::NoteNotFound` or `TnError::KeyShredded`.
3. **Vault Panic Wipe**:
   - Overwrite all local keys and salt with zeroizing passes:
     ```bash
     tn-cli panic-wipe --confirm
     ```
   - All SQLite files removed or scrubbed with `zeroize`.
