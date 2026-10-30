#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-server`: Untrusted sync server and transparency epoch publisher.
//!
//! Stores ciphertext, orders operations, issues signed receipts with merge deadlines,
//! publishes epoch trees, and exposes RFC 9162 / C2SP transparency endpoints.
//!
//! # M0 Status
//!
//! Skeleton binary. Server endpoints, Postgres backend, and sequencer arrive in M2;
//! epoch publisher and tree builders arrive in M3.

fn main() {
    println!("trustnotes server: skeleton for M0 (production server lands in M2/M3)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
