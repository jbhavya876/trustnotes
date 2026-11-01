#![no_main]

use libfuzzer_sys::fuzz_target;
use tn_tlog::Checkpoint;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize arbitrary bytes into a Checkpoint
    if let Ok(checkpoint) = Checkpoint::from_cbor(data) {
        // Exercise methods on the successfully parsed checkpoint
        let _ = checkpoint.signed_body();
        let _ = checkpoint.to_cbor();
    }
});
