#![no_main]

use libfuzzer_sys::fuzz_target;
use tn_merkle::{verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, MerkleRoot};

fuzz_target!(|data: &[u8]| {
    if data.len() < 72 {
        return;
    }

    // Extract leaf hash and root hash
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&data[0..32]);
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&data[32..64]);
    let root = MerkleRoot::from_bytes(root_bytes);

    let leaf_index = u64::from_be_bytes(data[64..72].try_into().unwrap());
    let rest = &data[72..];

    // Try inclusion proof with remaining bytes as sibling path
    let mut path = Vec::new();
    for chunk in rest.chunks_exact(32) {
        let mut node = [0u8; 32];
        node.copy_from_slice(chunk);
        path.push(node);
        if path.len() >= 64 {
            break;
        }
    }

    let tree_size = leaf_index.saturating_add(path.len() as u64).saturating_add(1);
    let proof = InclusionProof {
        leaf_index,
        tree_size,
        path: path.clone(),
    };

    let _ = verify_inclusion(&leaf_hash, &proof, &root);

    // Also fuzz consistency proof
    let old_root = root;
    let new_root = MerkleRoot::from_bytes(leaf_hash);
    let consistency_proof = ConsistencyProof {
        old_size: (leaf_index % 1000).saturating_add(1),
        new_size: tree_size,
        path,
    };
    let _ = verify_consistency(&old_root, &new_root, &consistency_proof);
});
