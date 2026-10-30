#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Concurrent sibling conflict detection and DAG branch management.
//!
//! Enforces ADR-0004 (Trade-off T7):
//! - Concurrent operations are preserved as siblings.
//! - HLC never silently overwrites data.
//! - Resolution operations reference all concurrent heads in `deps` to converge the DAG.

use std::collections::{HashMap, HashSet};
use tn_types::{Id16, Id32, OpKind};

use crate::op::Op;

/// Status of a note in the local DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictStatus {
    /// Note has a single active head with no concurrency.
    Single(Id32),
    /// Note has multiple concurrent heads that require explicit resolution.
    Conflicted {
        /// All concurrent head `op_id`s.
        heads: Vec<Id32>,
    },
    /// Note has been deleted/trashed.
    Deleted(Id32),
}

/// Tracks note version branches and identifies concurrent siblings.
#[derive(Debug, Default, Clone)]
pub struct NoteDagTracker {
    /// Object ID this tracker monitors.
    pub object_id: Id16,
    /// All op IDs seen for this object.
    all_ops: HashSet<Id32>,
    /// Direct dependencies: `op_id` -> set of deps it covers.
    deps_map: HashMap<Id32, Vec<Id32>>,
    /// Active heads (ops not superseded by any newer op's deps).
    active_heads: HashSet<Id32>,
    /// Last seen kind for each op.
    op_kinds: HashMap<Id32, OpKind>,
}

impl NoteDagTracker {
    /// Create a new DAG tracker for an object.
    #[must_use]
    pub fn new(object_id: Id16) -> Self {
        Self {
            object_id,
            all_ops: HashSet::new(),
            deps_map: HashMap::new(),
            active_heads: HashSet::new(),
            op_kinds: HashMap::new(),
        }
    }

    /// Ingests an operation on this note into the DAG.
    pub fn add_op(&mut self, op_id: Id32, op: &Op) {
        if op.object_id != self.object_id {
            return;
        }

        self.all_ops.insert(op_id);
        self.deps_map.insert(op_id, op.deps.clone());
        self.op_kinds.insert(op_id, op.kind);

        // Remove any prior heads that are superseded by this op's deps
        for dep in &op.deps {
            self.active_heads.remove(dep);
        }

        // Add this op as a current active head
        self.active_heads.insert(op_id);
    }

    /// Evaluates current conflict status.
    #[must_use]
    pub fn status(&self) -> ConflictStatus {
        if self.active_heads.len() <= 1 {
            match self.active_heads.iter().next() {
                Some(&head) => {
                    if let Some(OpKind::Delete | OpKind::Shred) = self.op_kinds.get(&head) {
                        ConflictStatus::Deleted(head)
                    } else {
                        ConflictStatus::Single(head)
                    }
                }
                None => ConflictStatus::Single(Id32::from_bytes([0u8; 32])),
            }
        } else {
            let mut heads: Vec<Id32> = self.active_heads.iter().copied().collect();
            heads.sort_by_key(|h| *h.as_bytes());
            ConflictStatus::Conflicted { heads }
        }
    }

    /// Checks if a proposed resolution op properly converges all current heads.
    #[must_use]
    pub fn is_valid_resolution(&self, resolution_deps: &[Id32]) -> bool {
        let dep_set: HashSet<Id32> = resolution_deps.iter().copied().collect();
        self.active_heads.is_subset(&dep_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;

    fn dummy_op(object_id: Id16, deps: Vec<Id32>, kind: OpKind) -> Op {
        Op {
            v: 1,
            account_id: Id32::from_bytes([1u8; 32]),
            device_id: Id32::from_bytes([2u8; 32]),
            lane_seq: 0,
            lane_prev: None,
            hlc: Hlc::new(100, 0),
            kind,
            object_id,
            nk_wrap: None,
            nonce: [0u8; 24],
            deps,
            ct: vec![],
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        }
    }

    #[test]
    fn test_concurrent_sibling_detection_and_resolution() {
        let obj = Id16::from_bytes([42u8; 16]);
        let mut tracker = NoteDagTracker::new(obj);

        let root_id = Id32::from_bytes([0x01; 32]);
        let root_op = dummy_op(obj, vec![], OpKind::Put);
        tracker.add_op(root_id, &root_op);

        assert_eq!(tracker.status(), ConflictStatus::Single(root_id));

        // Two concurrent edits from device A and device B, both with deps: [root_id]
        let branch_a_id = Id32::from_bytes([0x0A; 32]);
        let op_a = dummy_op(obj, vec![root_id], OpKind::Put);
        tracker.add_op(branch_a_id, &op_a);

        let branch_b_id = Id32::from_bytes([0x0B; 32]);
        let op_b = dummy_op(obj, vec![root_id], OpKind::Put);
        tracker.add_op(branch_b_id, &op_b);

        // Now both heads are active -> CONFLICTED!
        match tracker.status() {
            ConflictStatus::Conflicted { heads } => {
                assert_eq!(heads.len(), 2);
                assert!(heads.contains(&branch_a_id));
                assert!(heads.contains(&branch_b_id));
            }
            _ => panic!("Expected conflicted state"),
        }

        // Create a resolution op with deps: [branch_a_id, branch_b_id]
        assert!(tracker.is_valid_resolution(&[branch_a_id, branch_b_id]));

        let resolve_id = Id32::from_bytes([0x0C; 32]);
        let resolve_op = dummy_op(obj, vec![branch_a_id, branch_b_id], OpKind::Put);
        tracker.add_op(resolve_id, &resolve_op);

        // DAG converged back to single head!
        assert_eq!(tracker.status(), ConflictStatus::Single(resolve_id));
    }
}
