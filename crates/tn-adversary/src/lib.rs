#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-adversary`: Malicious server simulator and adversarial test harness.
//!
//! Drives clients against simulated server attacks across scenarios S1 through S17:
//! ciphertext tampering, history gaps, reordering, bad signatures, rollback,
//! split view, equivocation, unlogged key rotations, etc.
//!
//! # M0 Status
//!
//! Skeleton crate. Scenario drivers implemented in M3.

#[cfg(test)]
mod tests {
    #[test]
    fn adversary_lib_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
