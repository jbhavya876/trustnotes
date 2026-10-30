#![no_main]
// Placeholder fuzz target. Real fuzz targets are added in M1.
// This file exists to ensure the fuzz crate compiles.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // No-op placeholder
});
