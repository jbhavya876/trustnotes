#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Device lane management and continuity verification.
//!
//! Enforces:
//! - Strictly monotonic `lane_seq` starting at 0.
//! - Hash chaining: `lane_prev` points to previous `op_id`.
//! - Any gap or fork immediately emits `TnError::LaneDiscontinuity`.

use std::collections::HashMap;
use tn_types::{Id32, TnError};

use crate::op::Op;

/// State tracker for a single device's operation lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLaneTracker {
    /// Device identifier.
    pub device_id: Id32,
    /// Next expected sequence number in this lane.
    pub next_seq: u64,
    /// Identifier of the most recent operation in this lane.
    pub tip_op_id: Option<Id32>,
}

impl DeviceLaneTracker {
    /// Create a new empty lane tracker for a device.
    #[must_use]
    pub const fn new(device_id: Id32) -> Self {
        Self {
            device_id,
            next_seq: 0,
            tip_op_id: None,
        }
    }

    /// Verifies that an incoming `Op` satisfies lane continuity invariants.
    ///
    /// # Errors
    /// Returns `TnError::OrderViolation` if sequence number or previous hash does not match.
    pub fn verify_continuity(&self, op: &Op) -> Result<(), TnError> {
        if op.device_id != self.device_id {
            return Err(TnError::OrderViolation);
        }

        if op.lane_seq != self.next_seq {
            return Err(TnError::OrderViolation);
        }

        if op.lane_prev != self.tip_op_id {
            return Err(TnError::OrderViolation);
        }

        Ok(())
    }

    /// Updates the tracker state with the newly verified op.
    pub fn advance(&mut self, op_id: Id32) {
        self.tip_op_id = Some(op_id);
        self.next_seq = self.next_seq.saturating_add(1);
    }
}

/// Global tracker across all device lanes in an account.
#[derive(Debug, Default, Clone)]
pub struct LaneRegistry {
    lanes: HashMap<Id32, DeviceLaneTracker>,
}

impl LaneRegistry {
    /// Create a new lane registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lanes: HashMap::new(),
        }
    }

    /// Verifies continuity and advances the lane on success.
    ///
    /// # Errors
    /// Returns `TnError::LaneDiscontinuity` if continuity check fails.
    pub fn record_op(&mut self, op: &Op, op_id: Id32) -> Result<(), TnError> {
        let tracker = self
            .lanes
            .entry(op.device_id)
            .or_insert_with(|| DeviceLaneTracker::new(op.device_id));

        tracker.verify_continuity(op)?;
        tracker.advance(op_id);
        Ok(())
    }

    /// Retrieves current lane tip for a device.
    #[must_use]
    pub fn get_tip(&self, device_id: &Id32) -> Option<Id32> {
        self.lanes.get(device_id).and_then(|t| t.tip_op_id)
    }

    /// Retrieves next expected sequence number for a device.
    #[must_use]
    pub fn next_seq(&self, device_id: &Id32) -> u64 {
        self.lanes.get(device_id).map_or(0, |t| t.next_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use tn_types::{Id16, OpKind};

    fn make_test_op(device_id: Id32, seq: u64, prev: Option<Id32>) -> Op {
        Op {
            v: 1,
            account_id: Id32::from_bytes([0x01; 32]),
            device_id,
            lane_seq: seq,
            lane_prev: prev,
            hlc: Hlc::new(1000, 0),
            kind: OpKind::Put,
            object_id: Id16::from_bytes([0x02; 16]),
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct: vec![],
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        }
    }

    #[test]
    fn test_lane_continuity_happy_path() {
        let dev = Id32::from_bytes([0xAA; 32]);
        let mut reg = LaneRegistry::new();

        let op0 = make_test_op(dev, 0, None);
        let id0 = Id32::from_bytes([0x10; 32]);
        assert!(reg.record_op(&op0, id0).is_ok());

        let op1 = make_test_op(dev, 1, Some(id0));
        let id1 = Id32::from_bytes([0x11; 32]);
        assert!(reg.record_op(&op1, id1).is_ok());
    }

    #[test]
    fn test_lane_continuity_gap_rejected() {
        let dev = Id32::from_bytes([0xAA; 32]);
        let mut reg = LaneRegistry::new();

        let op_gap = make_test_op(dev, 1, None); // Should have been 0
        let id = Id32::from_bytes([0x10; 32]);
        assert!(matches!(
            reg.record_op(&op_gap, id),
            Err(TnError::OrderViolation)
        ));
    }
}
