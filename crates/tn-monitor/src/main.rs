#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-monitor`: Third-party auditor binary.

fn main() {
    println!("trustnotes monitor: skeleton for M0 (monitor daemon lands in M4)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn monitor_main_compiles() {
        assert_eq!(1 + 1, 2);
    }
}
