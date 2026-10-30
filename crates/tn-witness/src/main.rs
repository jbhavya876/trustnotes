#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-witness`: Independent witness daemon for the trustnotes transparency log.
//!
//! Stores latest cosigned checkpoint per log origin and cosigns new checkpoints
//! only when presented with a valid RFC 9162 consistency proof. Refuses cosignature
//! on equivocation or fork.
//!
//! # M0 Status
//!
//! Skeleton binary. Witness daemon and persistent state arrive in M4.

fn main() {
    println!("trustnotes witness: skeleton for M0 (witness daemon lands in M4)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn witness_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
