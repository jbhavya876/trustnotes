#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn`: The trustnotes command-line client.
//!
//! Provides CLI access to initialization, local note management, sync,
//! verification, device enrollment, and evidence export.
//!
//! # M0 Status
//!
//! Skeleton binary. Commands arrive in M1 (local) and M2 (sync).

fn main() {
    println!("tn: trustnotes CLI (M0 skeleton)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
