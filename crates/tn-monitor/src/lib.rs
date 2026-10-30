#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-monitor`: Third-party auditor library and CLI.
//!
//! Follows the global log and release log, verifies server signatures, consistency
//! between consecutive checkpoints, and witness cosignatures. Alerts on inconsistency,
//! missing cosignatures, or unlogged server-key changes.
//!
//! # M0 Status
//!
//! Skeleton library. Monitor logic lands in M4.

#[cfg(test)]
mod tests {
    #[test]
    fn monitor_lib_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
