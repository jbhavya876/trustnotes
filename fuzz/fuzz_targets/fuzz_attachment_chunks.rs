#![no_main]

use libfuzzer_sys::fuzz_target;
use tn_core::attachment::{open_attachment, EncryptedChunk};
use tn_oplog::AttachmentManifest;
use tn_types::Id16;

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }

    // 32 bytes note key, 16 bytes attachment id
    let mut note_key = [0u8; 32];
    note_key.copy_from_slice(&data[0..32]);

    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&data[32..48]);
    let attachment_id = Id16::from_bytes(id_bytes);

    let payload = &data[48..];

    // Construct a test manifest
    let manifest = AttachmentManifest {
        id: attachment_id,
        filename: "fuzz_test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        total_size: payload.len() as u64,
        chunk_size: 1024,
        chunk_hashes: vec![[0u8; 32]],
    };

    let chunk = EncryptedChunk {
        attachment_id,
        chunk_index: 0,
        ciphertext: payload.to_vec(),
    };

    let _ = open_attachment(&manifest, &[chunk], &note_key);
});
