#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Strict deterministic CBOR encoding and decoding wrapper.
//!
//! Enforces RFC 8949 §4.2 invariants:
//! 1. Integers must be encoded in the smallest possible number of bytes (canonical form).
//!    Non-shortest integer encodings are strictly rejected.
//! 2. Duplicate map keys are strictly rejected.
//! 3. Indefinite-length strings, byte strings, arrays, and maps are strictly rejected.
//! 4. Trailing bytes after the end of the expected data item are strictly rejected.

use crate::TnError;
use serde::{de::DeserializeOwned, Serialize};

/// Encode a value to canonical, deterministic CBOR bytes.
///
/// # Errors
/// Returns [`TnError::Decode`] if serialization fails.
pub fn encode_canonical<T: Serialize>(val: &T) -> Result<Vec<u8>, TnError> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf)
        .map_err(|e| TnError::Decode(format!("cbor serialization error: {e}")))?;

    // Self-validate that our own encoder produces canonical bytes
    validate_strict_cbor(&buf)?;
    Ok(buf)
}

/// Decode a value from strictly validated canonical CBOR bytes.
///
/// # Errors
/// Returns [`TnError::Decode`] if non-canonical, malformed, indefinite-length,
/// duplicate map keys, or trailing bytes are encountered.
pub fn decode_canonical<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TnError> {
    if bytes.is_empty() {
        return Err(TnError::Decode(
            "unexpected end of input (empty bytes)".to_string(),
        ));
    }

    // Step 1: Low-level syntactic validation of RFC 8949 §4.2 invariants
    let consumed = validate_strict_cbor(bytes)?;
    if consumed != bytes.len() {
        return Err(TnError::Decode(format!(
            "trailing extraneous bytes: parsed {consumed} of {} bytes",
            bytes.len()
        )));
    }

    // Step 2: Ciborium deserialization into target type
    ciborium::from_reader(bytes)
        .map_err(|e| TnError::Decode(format!("cbor deserialization error: {e}")))
}

/// Validates that `bytes` adheres to strict canonical CBOR rules.
/// Returns the number of bytes consumed by the top-level data item.
///
/// # Errors
///
/// Returns [`TnError::Decode`] if decoding or strict canonical validation fails.
pub fn validate_strict_cbor(bytes: &[u8]) -> Result<usize, TnError> {
    validate_item(bytes, 0)
}

fn validate_item(bytes: &[u8], offset: usize) -> Result<usize, TnError> {
    if offset >= bytes.len() {
        return Err(TnError::Decode("unexpected end of input".to_string()));
    }

    let initial = bytes[offset];
    let major = initial >> 5;
    let info = initial & 0x1f;

    // Check for forbidden indefinite length (info == 31)
    if info == 31 {
        return Err(TnError::Decode(
            "non-canonical CBOR: indefinite-length items are strictly rejected".to_string(),
        ));
    }

    // Check for unassigned/reserved additional information values (28..30)
    if (28..=30).contains(&info) {
        return Err(TnError::Decode(format!(
            "non-canonical CBOR: reserved additional info value {info}"
        )));
    }

    // Read and canonical-check the length or integer argument
    let (arg, arg_bytes) = read_argument(bytes, offset, info)?;
    let mut cursor = offset + 1 + arg_bytes;

    match major {
        // Major 0: Unsigned integer
        // Major 1: Negative integer
        // Major 7: Simple values & floats
        0 | 1 | 7 => Ok(cursor - offset),

        // Major 2: Byte string
        // Major 3: Text string (UTF-8)
        2 | 3 => {
            let len = usize::try_from(arg).map_err(|_| {
                TnError::Decode("string length exceeds target pointer width".to_string())
            })?;
            if cursor + len > bytes.len() {
                return Err(TnError::Decode("truncated string payload".to_string()));
            }
            if major == 3 {
                std::str::from_utf8(&bytes[cursor..cursor + len])
                    .map_err(|e| TnError::Decode(format!("invalid utf-8 text: {e}")))?;
            }
            cursor += len;
            Ok(cursor - offset)
        }

        // Major 4: Array of data items
        4 => {
            let count = usize::try_from(arg).map_err(|_| {
                TnError::Decode("array count exceeds target pointer width".to_string())
            })?;
            for _ in 0..count {
                let consumed = validate_item(bytes, cursor)?;
                cursor += consumed;
            }
            Ok(cursor - offset)
        }

        // Major 5: Map of key-value pairs
        5 => {
            let count = usize::try_from(arg).map_err(|_| {
                TnError::Decode("map count exceeds target pointer width".to_string())
            })?;
            let mut seen_keys: Vec<Vec<u8>> = Vec::with_capacity(count);

            for _ in 0..count {
                // Key
                let key_start = cursor;
                let key_len = validate_item(bytes, cursor)?;
                let key_bytes = bytes[key_start..key_start + key_len].to_vec();
                cursor += key_len;

                // Value
                let val_len = validate_item(bytes, cursor)?;
                cursor += val_len;

                // Check duplicate keys
                if seen_keys.contains(&key_bytes) {
                    return Err(TnError::Decode(
                        "non-canonical CBOR: duplicate map key detected".to_string(),
                    ));
                }
                seen_keys.push(key_bytes);
            }
            Ok(cursor - offset)
        }

        // Major 6: Tagged data item
        6 => {
            let item_len = validate_item(bytes, cursor)?;
            cursor += item_len;
            Ok(cursor - offset)
        }

        _ => unreachable!(),
    }
}

/// Reads the integer argument and validates that it was encoded in the shortest possible form.
fn read_argument(bytes: &[u8], offset: usize, info: u8) -> Result<(u64, usize), TnError> {
    match info {
        0..=23 => Ok((u64::from(info), 0)),
        24 => {
            if offset + 1 >= bytes.len() {
                return Err(TnError::Decode(
                    "truncated 1-byte integer argument".to_string(),
                ));
            }
            let val = u64::from(bytes[offset + 1]);
            // Non-shortest integer check: values 0..23 MUST be encoded directly in info
            if val < 24 {
                return Err(TnError::Decode(format!(
                    "non-canonical CBOR: non-shortest integer encoding: value {val} encoded in 1 byte"
                )));
            }
            Ok((val, 1))
        }
        25 => {
            if offset + 2 >= bytes.len() {
                return Err(TnError::Decode(
                    "truncated 2-byte integer argument".to_string(),
                ));
            }
            let val = u64::from(u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]));
            // Values <= 0xff MUST be encoded in 1 byte or directly
            if val <= 0xff {
                return Err(TnError::Decode(format!(
                    "non-canonical CBOR: non-shortest integer encoding: value {val} encoded in 2 bytes"
                )));
            }
            Ok((val, 2))
        }
        26 => {
            if offset + 4 >= bytes.len() {
                return Err(TnError::Decode(
                    "truncated 4-byte integer argument".to_string(),
                ));
            }
            let val = u64::from(u32::from_be_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]));
            // Values <= 0xffff MUST be encoded in 2 bytes
            if val <= 0xffff {
                return Err(TnError::Decode(format!(
                    "non-canonical CBOR: non-shortest integer encoding: value {val} encoded in 4 bytes"
                )));
            }
            Ok((val, 4))
        }
        27 => {
            if offset + 8 >= bytes.len() {
                return Err(TnError::Decode(
                    "truncated 8-byte integer argument".to_string(),
                ));
            }
            let val = u64::from_be_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
                bytes[offset + 8],
            ]);
            // Values <= 0xffff_ffff MUST be encoded in 4 bytes
            if val <= 0xffff_ffff {
                return Err(TnError::Decode(format!(
                    "non-canonical CBOR: non-shortest integer encoding: value {val} encoded in 8 bytes"
                )));
            }
            Ok((val, 8))
        }
        _ => Err(TnError::Decode(format!(
            "invalid CBOR additional info: {info}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrip_simple() {
        #[derive(Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct TestData {
            num: u32,
            text: String,
            bytes: Vec<u8>,
        }

        let original = TestData {
            num: 42,
            text: "trustnotes".to_string(),
            bytes: vec![1, 2, 3, 4],
        };

        let encoded = encode_canonical(&original).unwrap();
        let decoded: TestData = decode_canonical(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rejects_non_shortest_integer() {
        // 0x18 is 1-byte unsigned int follow; followed by 0x05 (value 5).
        // Value 5 must be encoded as 0x05 directly!
        let non_canonical = vec![0x18, 0x05];
        let res = validate_strict_cbor(&non_canonical);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("non-shortest integer"));
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x9f is indefinite-length array
        let indefinite = vec![0x9f, 0x01, 0xff];
        let res = validate_strict_cbor(&indefinite);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("indefinite-length"));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let original = 100u32;
        let mut encoded = encode_canonical(&original).unwrap();
        encoded.push(0x00); // Trailing extra byte
        let res: Result<u32, _> = decode_canonical(&encoded);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("trailing extraneous bytes"));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        // Map of 2 pairs with duplicate key 1: { 1: "a", 1: "b" }
        // 0xa2 (map len 2), 0x01, 0x61, 0x61 ("a"), 0x01, 0x61, 0x62 ("b")
        let dup_keys = vec![0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62];
        let res = validate_strict_cbor(&dup_keys);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("duplicate map key"));
    }
}
