#![no_main]

use libfuzzer_sys::fuzz_target;
use tn_oplog::Payload;
use tn_types::cbor::decode_canonical;

fuzz_target!(|data: &[u8]| {
    // 1. Attempt to decode arbitrary bytes as canonical CBOR into a Payload
    let _ = decode_canonical::<Payload>(data);

    // 2. Attempt to decode arbitrary bytes as a generic CBOR value
    let _ = decode_canonical::<ciborium::Value>(data);
});
