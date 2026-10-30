#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Hybrid Logical Clock (HLC) implementation.
//!
//! Provides advisory causal and physical ordering `(wall_ms, counter)` for operations.
//! Note: Per ADR-0004, HLC is advisory only; DAG dependencies (`deps`) define true causality.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hybrid Logical Clock timestamp `[wall_ms, counter]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hlc {
    /// Physical wall-clock time in milliseconds since Unix epoch.
    pub wall_ms: u64,
    /// Logical counter for disambiguating events within the same millisecond.
    pub counter: u32,
}

impl Hlc {
    /// Create a new HLC with explicit values.
    #[must_use]
    pub const fn new(wall_ms: u64, counter: u32) -> Self {
        Self { wall_ms, counter }
    }

    /// Read current physical time in milliseconds.
    #[must_use]
    pub fn current_physical_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
    }

    /// Generate next local event timestamp from a previous HLC.
    #[must_use]
    pub fn now(previous: Option<&Self>) -> Self {
        let physical = Self::current_physical_ms();
        match previous {
            None => Self {
                wall_ms: physical,
                counter: 0,
            },
            Some(prev) => {
                if physical > prev.wall_ms {
                    Self {
                        wall_ms: physical,
                        counter: 0,
                    }
                } else {
                    Self {
                        wall_ms: prev.wall_ms,
                        counter: prev.counter.saturating_add(1),
                    }
                }
            }
        }
    }

    /// Update HLC on receiving a remote message.
    #[must_use]
    pub fn update(local: &Self, remote: &Self) -> Self {
        let physical = Self::current_physical_ms();
        let max_wall = physical.max(local.wall_ms).max(remote.wall_ms);

        let counter = if max_wall == local.wall_ms && max_wall == remote.wall_ms {
            local.counter.max(remote.counter).saturating_add(1)
        } else if max_wall == local.wall_ms {
            local.counter.saturating_add(1)
        } else if max_wall == remote.wall_ms {
            remote.counter.saturating_add(1)
        } else {
            0
        };

        Self {
            wall_ms: max_wall,
            counter,
        }
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.wall_ms
            .cmp(&other.wall_ms)
            .then_with(|| self.counter.cmp(&other.counter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hlc_monotonicity() {
        let t1 = Hlc::now(None);
        let t2 = Hlc::now(Some(&t1));
        assert!(t2 >= t1);
    }

    #[test]
    fn test_hlc_update() {
        let l = Hlc::new(100, 2);
        let r = Hlc::new(150, 5);
        let updated = Hlc::update(&l, &r);
        assert!(updated.wall_ms >= 150);
        assert!(updated > l);
        assert!(updated > r);
    }
}
