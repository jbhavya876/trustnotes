#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! RFC 9162 append-only Merkle tree for TrustNotes.
//!
//! Domain separation (§2.1):
//! - Leaf:     `SHA-256(0x00 || data)`
//! - Interior: `SHA-256(0x01 || left || right)`
//!
//! Provides:
//! - [`MerkleTree`]: Append-only in-memory tree with O(log n) operations.
//! - [`verify_inclusion`]: RFC 9162 §2.1.3.2 inclusion proof verification.
//! - [`verify_consistency`]: RFC 9162 §2.1.4.2 consistency proof verification.
//! - [`Tile`]: C2SP `tlog-tiles` 256-entry tile encoding.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tn_types::TnError;

// ─── Domain separation prefixes (RFC 9162 §2.1) ──────────────────────────────

const LEAF_PREFIX: u8 = 0x00;
const INTERIOR_PREFIX: u8 = 0x01;

/// SHA-256 hash of a leaf entry.
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

/// SHA-256 hash of an interior node.
fn hash_interior(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([INTERIOR_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

// ─── MerkleRoot ──────────────────────────────────────────────────────────────

/// A SHA-256 Merkle tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Create a `MerkleRoot` from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ─── InclusionProof ──────────────────────────────────────────────────────────

/// An inclusion proof for a single leaf in an RFC 9162 tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// 0-indexed leaf position this proof is for.
    pub leaf_index: u64,
    /// Tree size at the time the proof was generated.
    pub tree_size: u64,
    /// Sibling hashes from leaf to root (RFC 9162 §2.1.3.1).
    pub path: Vec<[u8; 32]>,
}

// ─── ConsistencyProof ────────────────────────────────────────────────────────

/// A consistency proof showing tree at `old_size` is a prefix of tree at `new_size`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Tree size of the older tree.
    pub old_size: u64,
    /// Tree size of the newer tree.
    pub new_size: u64,
    /// Sub-root hashes demonstrating the relationship (RFC 9162 §2.1.4.1).
    pub path: Vec<[u8; 32]>,
}

// ─── Tile ─────────────────────────────────────────────────────────────────────

/// C2SP `tlog-tiles` compatible 256-entry tile.
#[derive(Debug, Clone)]
pub struct Tile {
    /// Tile level (0 = leaf hashes).
    pub level: u8,
    /// Tile index (0-based, counting 256-entry blocks at this level).
    pub index: u64,
    /// The hashes in this tile (up to 256 entries).
    pub hashes: Vec<[u8; 32]>,
}

// ─── MerkleTree ──────────────────────────────────────────────────────────────

/// Append-only RFC 9162 Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Creates a new empty Merkle tree.
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Returns the number of leaves appended.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Appends raw data as a new leaf (hashes it first).
    /// Returns the 0-based index of the newly appended leaf.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        let leaf = hash_leaf(data);
        self.append_leaf_hash(leaf)
    }

    /// Appends a pre-computed leaf hash (e.g., an `op_id`).
    /// Returns the 0-based index of the newly appended leaf.
    pub fn append_leaf_hash(&mut self, leaf_hash: [u8; 32]) -> u64 {
        let idx = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        idx
    }

    /// Computes the Merkle root of the entire tree.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot(mth(&self.leaves))
    }

    /// Generates an RFC 9162 inclusion proof for leaf at `index`.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if `index >= self.size()`.
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, TnError> {
        let n = self.size();
        if index >= n {
            return Err(TnError::Internal(format!(
                "inclusion_proof: index {index} out of range (tree size {n})"
            )));
        }
        let path = path_calc(&self.leaves, index);
        Ok(InclusionProof {
            leaf_index: index,
            tree_size: n,
            path,
        })
    }

    /// Generates an RFC 9162 consistency proof from `old_size` to `new_size` (= `self.size()`).
    ///
    /// # Errors
    /// Returns `TnError::Internal` if `old_size > self.size()` or `old_size == 0`.
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof, TnError> {
        let new_size = self.size();
        if old_size == 0 {
            return Err(TnError::Internal(
                "consistency_proof: old_size must be > 0".to_string(),
            ));
        }
        if old_size > new_size {
            return Err(TnError::Internal(format!(
                "consistency_proof: old_size {old_size} > new_size {new_size}"
            )));
        }
        if old_size == new_size {
            return Ok(ConsistencyProof {
                old_size,
                new_size,
                path: vec![],
            });
        }
        let path = subproof(&self.leaves, old_size as usize, true);
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path,
        })
    }

    /// Returns the C2SP tile at `(level, tile_index)`.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if `tile_index` is out of range.
    pub fn tile(&self, level: u8, tile_index: u64) -> Result<Tile, TnError> {
        let hashes_at_level = self.hashes_at_level(level);
        let start = (tile_index * 256) as usize;
        if start >= hashes_at_level.len() {
            return Err(TnError::Internal(format!(
                "tile: level {level} index {tile_index} out of range"
            )));
        }
        let end = (start + 256).min(hashes_at_level.len());
        Ok(Tile {
            level,
            index: tile_index,
            hashes: hashes_at_level[start..end].to_vec(),
        })
    }

    fn hashes_at_level(&self, level: u8) -> Vec<[u8; 32]> {
        let mut current = self.leaves.clone();
        for _ in 0..level {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i + 1 < current.len() {
                next.push(hash_interior(&current[i], &current[i + 1]));
                i += 2;
            }
            if i < current.len() {
                next.push(current[i]);
            }
            current = next;
        }
        current
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RFC 9162 §2.1.1 Merkle Tree Hash (MTH) ──────────────────────────────────

fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - (n - 1).leading_zeros() - 1)
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        n => {
            let k = split_point(n);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            hash_interior(&left, &right)
        }
    }
}

// ─── RFC 9162 §2.1.3.1 Inclusion Proof Generation ────────────────────────────

fn path_calc(leaves: &[[u8; 32]], m: u64) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    let m_idx = m as usize;
    if m_idx < k {
        let mut p = path_calc(&leaves[..k], m);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path_calc(&leaves[k..], (m_idx - k) as u64);
        p.push(mth(&leaves[..k]));
        p
    }
}

// ─── RFC 9162 §2.1.4.1 Consistency Proof Generation ──────────────────────────

fn subproof(leaves: &[[u8; 32]], m: usize, b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![mth(leaves)];
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(&leaves[..k], m, b);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(&leaves[k..], m - k, false);
        p.push(mth(&leaves[..k]));
        p
    }
}

// ─── RFC 9162 §2.1.3.2 Verifying an Inclusion Proof ──────────────────────────

/// Verifies an RFC 9162 inclusion proof.
///
/// # Errors
/// - `TnError::RootMismatch` if proof verification fails or root does not match.
/// - `TnError::Internal` on invalid proof structure.
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    proof: &InclusionProof,
    expected_root: &MerkleRoot,
) -> Result<(), TnError> {
    if proof.leaf_index >= proof.tree_size {
        return Err(TnError::Internal("leaf_index >= tree_size".to_string()));
    }

    let mut fn_idx = proof.leaf_index;
    let mut sn_idx = proof.tree_size - 1;
    let mut r = *leaf_hash;

    for p in &proof.path {
        if sn_idx == 0 {
            return Err(TnError::RootMismatch);
        }
        if (fn_idx & 1) == 1 || fn_idx == sn_idx {
            r = hash_interior(p, &r);
            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn_idx >>= 1;
            }
        } else {
            r = hash_interior(&r, p);
        }
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    if sn_idx == 0 && constant_time_eq(&r, expected_root.as_bytes()) {
        Ok(())
    } else {
        Err(TnError::RootMismatch)
    }
}

// ─── RFC 9162 §2.1.4.2 Verifying Consistency between Two Tree Heads ──────────

/// Verifies an RFC 9162 consistency proof between `old_root` and `new_root`.
///
/// # Errors
/// - `TnError::Rollback` if `new_size < old_size`.
/// - `TnError::RootMismatch` if proof verification fails or roots do not match.
/// - `TnError::Internal` on invalid parameters.
pub fn verify_consistency(
    old_root: &MerkleRoot,
    new_root: &MerkleRoot,
    proof: &ConsistencyProof,
) -> Result<(), TnError> {
    let first = proof.old_size;
    let second = proof.new_size;

    if second < first {
        return Err(TnError::Rollback);
    }
    if first == 0 {
        return Err(TnError::Internal("first must be > 0".to_string()));
    }
    if first == second {
        if proof.path.is_empty() && constant_time_eq(old_root.as_bytes(), new_root.as_bytes()) {
            return Ok(());
        }
        return Err(TnError::RootMismatch);
    }
    if proof.path.is_empty() {
        return Err(TnError::RootMismatch);
    }

    // Step 2: If first is an exact power of 2, prepend old_root to consistency_path
    let mut c_path: Vec<[u8; 32]> = Vec::with_capacity(proof.path.len() + 1);
    if (first & (first - 1)) == 0 {
        c_path.push(*old_root.as_bytes());
    }
    c_path.extend_from_slice(&proof.path);

    // Step 3: fn = first - 1, sn = second - 1
    let mut fn_idx = first - 1;
    let mut sn_idx = second - 1;

    // Step 4: If LSB(fn) is set, right-shift both until LSB(fn) is not set
    while (fn_idx & 1) == 1 {
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    // Step 5: Set both fr and sr to first value in consistency_path
    let mut fr = c_path[0];
    let mut sr = c_path[0];

    // Step 6: For each subsequent value c in consistency_path:
    for c in &c_path[1..] {
        if sn_idx == 0 {
            return Err(TnError::RootMismatch);
        }
        if (fn_idx & 1) == 1 || fn_idx == sn_idx {
            fr = hash_interior(c, &fr);
            sr = hash_interior(c, &sr);
            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn_idx >>= 1;
            }
        } else {
            sr = hash_interior(&sr, c);
        }
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    // Step 7: Compare fr against old_root, sr against new_root, and sn == 0
    let fr_ok = constant_time_eq(&fr, old_root.as_bytes());
    let sr_ok = constant_time_eq(&sr, new_root.as_bytes());

    if fr_ok && sr_ok && sn_idx == 0 {
        Ok(())
    } else {
        Err(TnError::RootMismatch)
    }
}

/// Constant-time byte slice comparison (prevents timing side-channels).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Hashes raw data as a Merkle leaf (for use as an `op_id` leaf hash).
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    hash_leaf(data)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_zero() {
        let t = MerkleTree::new();
        assert_eq!(*t.root().as_bytes(), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let mut t = MerkleTree::new();
        let data = b"leaf0";
        t.append(data);
        let expected = hash_leaf(data);
        assert_eq!(*t.root().as_bytes(), expected);
    }

    #[test]
    fn two_leaf_root_is_interior_hash() {
        let mut t = MerkleTree::new();
        t.append(b"leaf0");
        t.append(b"leaf1");
        let l0 = hash_leaf(b"leaf0");
        let l1 = hash_leaf(b"leaf1");
        let expected = hash_interior(&l0, &l1);
        assert_eq!(*t.root().as_bytes(), expected);
    }

    #[test]
    fn same_inputs_produce_same_root() {
        let leaves = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let mut t1 = MerkleTree::new();
        let mut t2 = MerkleTree::new();
        for l in &leaves {
            t1.append(l.as_bytes());
            t2.append(l.as_bytes());
        }
        assert_eq!(t1.root(), t2.root());
    }

    fn make_rfc_tree() -> MerkleTree {
        let mut t = MerkleTree::new();
        for i in 0u8..8u8 {
            t.append(format!("d{i}").as_bytes());
        }
        t
    }

    #[test]
    fn rfc9162_8_leaf_tree_size() {
        let t = make_rfc_tree();
        assert_eq!(t.size(), 8);
    }

    #[test]
    fn inclusion_proof_verifies_for_all_leaves_in_8_leaf_tree() {
        let t = make_rfc_tree();
        let root = t.root();
        for i in 0u64..8u64 {
            let leaf = hash_leaf(format!("d{i}").as_bytes());
            let proof = t.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf, &proof, &root).unwrap_or_else(|_| {
                panic!("inclusion proof failed for leaf {i}");
            });
        }
    }

    #[test]
    fn consistency_proof_verifies_for_growing_tree() {
        let mut t = MerkleTree::new();
        let mut roots = Vec::new();
        for i in 0u8..8u8 {
            t.append(format!("d{i}").as_bytes());
            roots.push((t.size(), t.root()));
        }
        let final_root = roots.last().unwrap().1;
        let final_size = 8u64;
        for (old_size, old_root) in &roots[..roots.len() - 1] {
            let proof = t.consistency_proof(*old_size).unwrap();
            verify_consistency(old_root, &final_root, &proof).unwrap_or_else(|e| {
                panic!("consistency proof failed from {old_size} to {final_size}: {e:?}");
            });
        }
    }

    #[test]
    fn tampered_inclusion_proof_yields_root_mismatch() {
        let mut t = MerkleTree::new();
        for i in 0u8..4u8 {
            t.append(format!("d{i}").as_bytes());
        }
        let root = t.root();
        let leaf = hash_leaf(b"d2");
        let mut proof = t.inclusion_proof(2).unwrap();

        proof.path[0][0] ^= 0x01;

        let result = verify_inclusion(&leaf, &proof, &root);
        assert!(
            matches!(result, Err(TnError::RootMismatch)),
            "expected RootMismatch, got {result:?}"
        );
    }

    #[test]
    fn wrong_leaf_in_inclusion_proof_yields_root_mismatch() {
        let mut t = MerkleTree::new();
        for i in 0u8..4u8 {
            t.append(format!("d{i}").as_bytes());
        }
        let root = t.root();
        let wrong_leaf = hash_leaf(b"wrong-data");
        let proof = t.inclusion_proof(2).unwrap();
        let result = verify_inclusion(&wrong_leaf, &proof, &root);
        assert!(matches!(result, Err(TnError::RootMismatch)));
    }

    #[test]
    fn out_of_bounds_inclusion_proof_returns_error() {
        let mut t = MerkleTree::new();
        t.append(b"leaf0");
        let result = t.inclusion_proof(5);
        assert!(matches!(result, Err(TnError::Internal(_))));
    }

    #[test]
    fn consistency_proof_old_size_exceeds_tree_size_returns_error() {
        let mut t = MerkleTree::new();
        t.append(b"leaf0");
        let result = t.consistency_proof(999);
        assert!(matches!(result, Err(TnError::Internal(_))));
    }

    #[test]
    fn consistency_verify_with_rollback_new_less_than_old_returns_rollback() {
        let mut t = MerkleTree::new();
        for i in 0u8..4u8 {
            t.append(format!("d{i}").as_bytes());
        }
        let old_root = t.root();
        let new_root = MerkleTree::new().root();
        let proof = ConsistencyProof {
            old_size: 4,
            new_size: 2,
            path: vec![],
        };
        let result = verify_consistency(&old_root, &new_root, &proof);
        assert!(matches!(result, Err(TnError::Rollback)));
    }

    #[test]
    fn tile_level_0_returns_leaf_hashes() {
        let mut t = MerkleTree::new();
        for i in 0u8..4u8 {
            t.append(format!("d{i}").as_bytes());
        }
        let tile = t.tile(0, 0).unwrap();
        assert_eq!(tile.level, 0);
        assert_eq!(tile.index, 0);
        assert_eq!(tile.hashes.len(), 4);
        assert_eq!(tile.hashes[0], hash_leaf(b"d0"));
    }

    #[test]
    fn tile_out_of_range_returns_error() {
        let mut t = MerkleTree::new();
        t.append(b"leaf0");
        let result = t.tile(0, 5);
        assert!(matches!(result, Err(TnError::Internal(_))));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_inclusion_verifies_for_all_leaves(n in 1usize..32usize, seed in 0u64..100u64) {
            let mut t = MerkleTree::new();
            for i in 0..n {
                t.append(format!("leaf-{seed}-{i}").as_bytes());
            }
            let root = t.root();
            for i in 0..n as u64 {
                let leaf_data = format!("leaf-{seed}-{i}");
                let leaf = hash_leaf(leaf_data.as_bytes());
                let proof = t.inclusion_proof(i).unwrap();
                prop_assert!(verify_inclusion(&leaf, &proof, &root).is_ok(),
                    "inclusion proof failed for leaf {i} in {n}-leaf tree");
            }
        }

        #[test]
        fn prop_consistency_verifies_all_prefixes(n in 2usize..32usize, seed in 0u64..100u64) {
            let mut t = MerkleTree::new();
            let mut snapshots: Vec<(u64, MerkleRoot)> = Vec::new();
            for i in 0..n {
                t.append(format!("leaf-{seed}-{i}").as_bytes());
                snapshots.push((t.size(), t.root()));
            }
            let (final_size, final_root) = snapshots.last().unwrap();
            for (old_size, old_root) in &snapshots[..snapshots.len() - 1] {
                let proof = t.consistency_proof(*old_size).unwrap();
                prop_assert_eq!(proof.old_size, *old_size);
                prop_assert_eq!(proof.new_size, *final_size);
                prop_assert!(verify_consistency(old_root, final_root, &proof).is_ok(),
                    "consistency proof failed from {old_size} to {final_size}");
            }
        }

        #[test]
        fn prop_tampered_inclusion_fails(n in 2usize..16usize, idx in 0usize..16usize, seed in 0u64..50u64) {
            let idx = (idx % n) as u64;
            let mut t = MerkleTree::new();
            for i in 0..n {
                t.append(format!("leaf-{seed}-{i}").as_bytes());
            }
            let root = t.root();
            let leaf = hash_leaf(format!("leaf-{seed}-{idx}").as_bytes());
            let mut proof = t.inclusion_proof(idx).unwrap();
            if proof.path.is_empty() { return Ok(()); }
            proof.path[0][0] ^= 0xFF;
            prop_assert!(verify_inclusion(&leaf, &proof, &root).is_err(),
                "tampered proof should fail");
        }
    }
}
