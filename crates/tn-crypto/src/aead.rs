#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Authenticated Encryption with Associated Data (AEAD) using XChaCha20-Poly1305.
//!
//! Enforces:
//! - Random 24-byte nonce generated internally via `getrandom`. Callers cannot pass nonces.
//! - Nonce prepended to ciphertext: `nonce (24B) || ciphertext || tag (16B)`.
//! - Typed errors: Tampering emits `TnError::CiphertextTampered`.
//! - Padding applied before encryption to prevent length analysis (A1, A3).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use tn_types::{Id16, TnError};

use crate::keys::{LocalStorageKey, NoteKey, VaultKey};
use crate::labels::LABEL_NK_WRAP;
use crate::padding::{pad, unpad};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + TAG_LEN;

/// Encrypts plaintext with XChaCha20-Poly1305 using an internal CSPRNG nonce.
/// Nonce is prepended to the returned bytes: `nonce (24B) || ciphertext (includes tag 16B)`.
fn encrypt_internal(
    key_bytes: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, TnError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| TnError::Internal(format!("Entropy generation failed: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
        .map_err(|e| TnError::Internal(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ct = cipher
        .encrypt(nonce, payload)
        .map_err(|e| TnError::Internal(format!("Encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts ciphertext where first 24 bytes are the nonce.
fn decrypt_internal(
    key_bytes: &[u8; 32],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TnError> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(TnError::CiphertextTampered);
    }

    let (nonce_bytes, ct_bytes) = ciphertext.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key_bytes)
        .map_err(|e| TnError::Internal(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(nonce_bytes);

    let payload = Payload { msg: ct_bytes, aad };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| TnError::CiphertextTampered)
}

/// Wraps a Note Key (NK) under the Vault Key (VK).
///
/// AAD: `object_id (16B) || "tn/v1/nk-wrap"`
///
/// # Errors
/// Emits `TnError::Internal` if encryption fails.
pub fn wrap_note_key(vk: &VaultKey, object_id: Id16, nk: &NoteKey) -> Result<Vec<u8>, TnError> {
    let mut aad = Vec::with_capacity(16 + LABEL_NK_WRAP.len());
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(LABEL_NK_WRAP.as_bytes());

    encrypt_internal(vk.expose_bytes(), &aad, nk.expose_bytes())
}

/// Unwraps a Note Key (NK) using the Vault Key (VK).
///
/// # Errors
/// Emits `TnError::CiphertextTampered` if ciphertext or AAD has been altered.
pub fn unwrap_note_key(vk: &VaultKey, object_id: Id16, wrapped: &[u8]) -> Result<NoteKey, TnError> {
    let mut aad = Vec::with_capacity(16 + LABEL_NK_WRAP.len());
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(LABEL_NK_WRAP.as_bytes());

    let pt = decrypt_internal(vk.expose_bytes(), &aad, wrapped)?;
    if pt.len() != 32 {
        return Err(TnError::CiphertextTampered);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&pt);
    Ok(NoteKey::from_bytes(key))
}

/// Pads and encrypts note plaintext under Note Key (NK).
///
/// # Errors
/// Returns `TnError` if padding or encryption fails.
pub fn seal_note_payload(nk: &NoteKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TnError> {
    let padded = pad(plaintext);
    encrypt_internal(nk.expose_bytes(), aad, &padded)
}

/// Decrypts and unpads note ciphertext under Note Key (NK).
///
/// # Errors
/// Returns `TnError::CiphertextTampered` on authentication failure or invalid padding.
pub fn open_note_payload(nk: &NoteKey, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TnError> {
    let padded = decrypt_internal(nk.expose_bytes(), aad, ciphertext)?;
    unpad(&padded).map_err(|_| TnError::CiphertextTampered)
}

/// Seals local storage database columns under `LocalStorageKey` (LSK).
///
/// # Errors
/// Returns `TnError` on encryption failure.
pub fn seal_local(lsk: &LocalStorageKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TnError> {
    encrypt_internal(lsk.expose_bytes(), aad, plaintext)
}

/// Opens local storage database columns under `LocalStorageKey` (LSK).
///
/// # Errors
/// Returns `TnError::CiphertextTampered` on MAC verification failure.
pub fn open_local(
    lsk: &LocalStorageKey,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TnError> {
    decrypt_internal(lsk.expose_bytes(), aad, ciphertext)
}

/// Encrypts raw data with a 32-byte symmetric key.
///
/// # Errors
/// Returns `TnError` on encryption failure.
pub fn seal_raw(key_bytes: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TnError> {
    encrypt_internal(key_bytes, aad, plaintext)
}

/// Decrypts raw data with a 32-byte symmetric key.
///
/// # Errors
/// Returns `TnError::CiphertextTampered` on MAC verification failure.
pub fn open_raw(key_bytes: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TnError> {
    decrypt_internal(key_bytes, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_note_key() {
        let vk = VaultKey::from_bytes([7u8; 32]);
        let nk = NoteKey::from_bytes([9u8; 32]);
        let object_id = Id16::from_bytes([1u8; 16]);

        let wrapped = wrap_note_key(&vk, object_id, &nk).unwrap();
        assert_eq!(wrapped.len(), 24 + 32 + 16);

        let unwrapped = unwrap_note_key(&vk, object_id, &wrapped).unwrap();
        assert_eq!(unwrapped.expose_bytes(), nk.expose_bytes());

        // Tamper with ciphertext byte
        let mut corrupted = wrapped.clone();
        corrupted[30] ^= 0x01;
        assert!(matches!(
            unwrap_note_key(&vk, object_id, &corrupted),
            Err(TnError::CiphertextTampered)
        ));

        // Wrong object_id (AAD mismatch)
        let wrong_obj = Id16::from_bytes([2u8; 16]);
        assert!(matches!(
            unwrap_note_key(&vk, wrong_obj, &wrapped),
            Err(TnError::CiphertextTampered)
        ));
    }

    #[test]
    fn test_seal_open_note_payload_with_padding() {
        let nk = NoteKey::from_bytes([13u8; 32]);
        let aad = b"test-aad-binding";
        let plaintext = b"Hello, secret TrustNotes vault!";

        let ct = seal_note_payload(&nk, aad, plaintext).unwrap();
        assert_eq!(ct.len(), 24 + 256 + 16);

        let pt = open_note_payload(&nk, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);

        // Tamper with payload
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(matches!(
            open_note_payload(&nk, aad, &tampered),
            Err(TnError::CiphertextTampered)
        ));
    }
}
