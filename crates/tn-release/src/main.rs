#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-release`: Reproducible build verification, signing ceremonies, and release log entries.
//!
//! Tools for independent builders to reproduce release artifacts byte-for-byte,
//! perform offline signing ceremonies, and append entries to the release transparency log.
//!
//! # M0 Status
//!
//! Skeleton binary. Release log and verification tooling arrive in M4.

fn main() {
    println!("tn-release: release management and verification tool (M0 skeleton)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn release_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
