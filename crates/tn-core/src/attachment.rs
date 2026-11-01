#![forbid(unsafe_code)]

//! Chunked Encrypted Attachments for TrustNotes (SPEC §M6, Section 401).
//!
//! Large attachments are split into 1 MiB (1,048,576 byte) chunks.
//! Each chunk is independently encrypted under an attachment key derived from the
//! note key using HKDF-SHA-256 with info `"tn/v1/attachment\0"`.
//! The chunk ciphertexts are authenticated with XChaCha20-Poly1305 using the attachment ID
//! as AAD. The note payload manifest stores the chunk size, total size, and SHA-256
//! hashes of each decrypted chunk.

use sha2::{Digest, Sha256};
use tn_crypto::aead::{open_raw, seal_raw};
use tn_crypto::kdf::derive_hkdf_sha256;
use tn_oplog::AttachmentManifest;
use tn_types::{Id16, TnError};

/// Default chunk size is 1 MiB (1,048,576 bytes).
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// HKDF info label for attachment key derivation.
pub const LABEL_ATTACHMENT_KDF: &[u8] = b"tn/v1/attachment\0";

/// Represents an encrypted chunk ready to be stored or uploaded to `/v1/blobs/{id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedChunk {
    /// Attachment ID this chunk belongs to.
    pub attachment_id: Id16,
    /// 0-based chunk index.
    pub chunk_index: u32,
    /// Ciphertext bytes (including AEAD nonce and tag).
    pub ciphertext: Vec<u8>,
}

/// Derives the 32-byte symmetric attachment key from a NoteKey.
#[must_use]
pub fn derive_attachment_key(note_key_bytes: &[u8; 32], attachment_id: &Id16) -> [u8; 32] {
    derive_hkdf_sha256(
        note_key_bytes,
        Some(attachment_id.as_bytes()),
        LABEL_ATTACHMENT_KDF,
    )
}

/// Splits a plaintext byte slice into 1 MiB chunks and encrypts each chunk.
///
/// Returns the manifest to be embedded in `Payload` and the list of encrypted chunks.
///
/// # Errors
/// Returns `TnError` if random generation or encryption fails.
pub fn seal_attachment(
    filename: &str,
    mime_type: &str,
    data: &[u8],
    note_key_bytes: &[u8; 32],
) -> Result<(AttachmentManifest, Vec<EncryptedChunk>), TnError> {
    seal_attachment_with_chunk_size(
        filename,
        mime_type,
        data,
        note_key_bytes,
        DEFAULT_CHUNK_SIZE,
    )
}

/// Splits a plaintext byte slice with a custom chunk size (useful for testing).
///
/// # Errors
/// Returns `TnError` if random generation or encryption fails.
pub fn seal_attachment_with_chunk_size(
    filename: &str,
    mime_type: &str,
    data: &[u8],
    note_key_bytes: &[u8; 32],
    chunk_size: usize,
) -> Result<(AttachmentManifest, Vec<EncryptedChunk>), TnError> {
    let mut id_bytes = [0u8; 16];
    getrandom::getrandom(&mut id_bytes)
        .map_err(|e| TnError::Internal(format!("Failed to generate attachment ID: {e}")))?;
    let attachment_id = Id16::from_bytes(id_bytes);

    let attachment_key = derive_attachment_key(note_key_bytes, &attachment_id);
    let mut chunk_hashes = Vec::new();
    let mut encrypted_chunks = Vec::new();

    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[][..]]
    } else {
        data.chunks(chunk_size).collect()
    };

    for (i, chunk_bytes) in chunks.iter().enumerate() {
        let chunk_index =
            u32::try_from(i).map_err(|_| TnError::Internal("Chunk index overflow".into()))?;

        // Compute SHA-256 hash of plaintext chunk
        let mut hasher = Sha256::new();
        hasher.update(chunk_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        chunk_hashes.push(hash);

        // AAD binds attachment_id and chunk_index
        let mut aad = Vec::with_capacity(20);
        aad.extend_from_slice(attachment_id.as_bytes());
        aad.extend_from_slice(&chunk_index.to_be_bytes());

        let ciphertext = seal_raw(&attachment_key, &aad, chunk_bytes)?;
        encrypted_chunks.push(EncryptedChunk {
            attachment_id,
            chunk_index,
            ciphertext,
        });
    }

    let manifest = AttachmentManifest {
        id: attachment_id,
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        total_size: data.len() as u64,
        chunk_size: chunk_size as u32,
        chunk_hashes,
    };

    Ok((manifest, encrypted_chunks))
}

/// Decrypts and reassembles chunks into original plaintext according to the manifest.
///
/// # Errors
/// Returns `TnError::AttachmentTampered` if any chunk is missing, out-of-order,
/// tampered, or hash verification fails.
pub fn open_attachment(
    manifest: &AttachmentManifest,
    chunks: &[EncryptedChunk],
    note_key_bytes: &[u8; 32],
) -> Result<Vec<u8>, TnError> {
    if chunks.len() != manifest.chunk_hashes.len() {
        return Err(TnError::AttachmentTampered);
    }

    let attachment_key = derive_attachment_key(note_key_bytes, &manifest.id);
    let mut reassembled = Vec::with_capacity(manifest.total_size as usize);

    for (i, expected_hash) in manifest.chunk_hashes.iter().enumerate() {
        let chunk_index =
            u32::try_from(i).map_err(|_| TnError::Internal("Chunk index overflow".into()))?;
        let chunk = chunks.get(i).ok_or(TnError::AttachmentTampered)?;

        if chunk.attachment_id != manifest.id || chunk.chunk_index != chunk_index {
            return Err(TnError::AttachmentTampered);
        }

        let mut aad = Vec::with_capacity(20);
        aad.extend_from_slice(manifest.id.as_bytes());
        aad.extend_from_slice(&chunk_index.to_be_bytes());

        let plaintext = open_raw(&attachment_key, &aad, &chunk.ciphertext)
            .map_err(|_| TnError::AttachmentTampered)?;

        // Verify SHA-256 hash matches manifest
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let actual_hash: [u8; 32] = hasher.finalize().into();

        if &actual_hash != expected_hash {
            return Err(TnError::AttachmentTampered);
        }

        reassembled.extend_from_slice(&plaintext);
    }

    if reassembled.len() as u64 != manifest.total_size {
        return Err(TnError::AttachmentTampered);
    }

    Ok(reassembled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attachment_chunking_roundtrip() {
        let note_key = [42u8; 32];
        let original_data = vec![0xAB; 2500]; // 2.5 KB data with 1 KB chunk size

        let (manifest, chunks) = seal_attachment_with_chunk_size(
            "research_notes.pdf",
            "application/pdf",
            &original_data,
            &note_key,
            1024,
        )
        .expect("seal failed");

        assert_eq!(manifest.filename, "research_notes.pdf");
        assert_eq!(manifest.mime_type, "application/pdf");
        assert_eq!(manifest.total_size, 2500);
        assert_eq!(manifest.chunk_size, 1024);
        assert_eq!(manifest.chunk_hashes.len(), 3); // 1024 + 1024 + 452
        assert_eq!(chunks.len(), 3);

        let reassembled = open_attachment(&manifest, &chunks, &note_key).expect("open failed");
        assert_eq!(reassembled, original_data);
    }

    #[test]
    fn test_attachment_tampered_chunk_fails() {
        let note_key = [42u8; 32];
        let original_data = vec![0xBC; 1500];

        let (manifest, mut chunks) = seal_attachment_with_chunk_size(
            "secrets.txt",
            "text/plain",
            &original_data,
            &note_key,
            512,
        )
        .expect("seal failed");

        // Tamper 1 byte in chunk 1 ciphertext
        if let Some(byte) = chunks[1].ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let err = open_attachment(&manifest, &chunks, &note_key);
        assert!(matches!(err, Err(TnError::AttachmentTampered)));
    }

    #[test]
    fn test_attachment_reordered_chunks_fails() {
        let note_key = [42u8; 32];
        let original_data = vec![0xCD; 2048];

        let (manifest, mut chunks) = seal_attachment_with_chunk_size(
            "image.png",
            "image/png",
            &original_data,
            &note_key,
            1024,
        )
        .expect("seal failed");

        // Swap chunk 0 and chunk 1
        chunks.swap(0, 1);

        let err = open_attachment(&manifest, &chunks, &note_key);
        assert!(matches!(err, Err(TnError::AttachmentTampered)));
    }

    #[test]
    fn test_attachment_wrong_key_fails() {
        let note_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let original_data = b"confidential payload";

        let (manifest, chunks) = seal_attachment_with_chunk_size(
            "doc.txt",
            "text/plain",
            original_data,
            &note_key,
            1024,
        )
        .expect("seal failed");

        let err = open_attachment(&manifest, &chunks, &wrong_key);
        assert!(matches!(err, Err(TnError::AttachmentTampered)));
    }
}
