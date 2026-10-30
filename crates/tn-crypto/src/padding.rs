#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! ISO/IEC 7816-4 and Padme plaintext padding.
//!
//! Padding eliminates metadata and character-count leakage across network transport
//! and stored ciphertexts.
//!
//! # Specification
//!
//! 1. Delimiter: append byte `0x80` to the plaintext, followed by `0x00` bytes.
//! 2. Bounded bucket rounding:
//!    - $\le 256 \to 256$
//!    - $\le 512 \to 512$
//!    - $\le 1024 \to 1024$
//!    - $\le 2048 \to 2048$
//!    - $\le 4096 \to 4096$
//! 3. Above 4096 bytes: [Padme](https://lbarman.ch/blog/padme/) rounding.

use tn_types::TnError;

/// Pad a plaintext slice into a padded buffer adhering to bucket boundaries.
#[must_use]
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let unpadded_len = plaintext.len();
    // At minimum 1 delimiter byte (0x80) is required
    let needed_len = unpadded_len + 1;
    let target_len = compute_padded_len(needed_len);

    let mut out = Vec::with_capacity(target_len);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(target_len, 0x00);
    out
}

/// Remove ISO/IEC 7816-4 padding from decrypted plaintext.
///
/// # Errors
///
/// Returns [`TnError::Decode`] if the padding is malformed or missing delimiter `0x80`.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, TnError> {
    if padded.is_empty() {
        return Err(TnError::Decode("padded buffer is empty".to_string()));
    }

    // Scan backwards past all trailing 0x00 bytes
    let mut i = padded.len();
    while i > 0 && padded[i - 1] == 0x00 {
        i -= 1;
    }

    if i == 0 || padded[i - 1] != 0x80 {
        return Err(TnError::Decode(
            "malformed padding: missing 0x80 delimiter".to_string(),
        ));
    }

    Ok(padded[..i - 1].to_vec())
}

/// Compute bucket length for a given payload size (including delimiter).
#[must_use]
pub fn compute_padded_len(len: usize) -> usize {
    if len <= 256 {
        256
    } else if len <= 512 {
        512
    } else if len <= 1024 {
        1024
    } else if len <= 2048 {
        2048
    } else if len <= 4096 {
        4096
    } else {
        padme(len)
    }
}

/// Padme algorithm (PURB, Barman et al.) for payloads > 4096 bytes.
#[must_use]
pub fn padme(len: usize) -> usize {
    if len <= 1 {
        return len;
    }
    let len_u64 = len as u64;
    let e = len_u64.ilog2(); // floor(log2(len))
    let s = u64::from(e).ilog2(); // floor(log2(e))

    if e <= s + 1 {
        return len;
    }

    let last_bits = (e - s - 1) as usize;
    let bit_mask = (1usize << last_bits) - 1;
    (len + bit_mask) & !bit_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_padding() {
        let cases: &[&[u8]] = &[
            b"",
            b"hello world",
            &[0x42; 255],
            &[0x42; 256],
            &[0x42; 500],
            &[0x42; 1023],
            &[0x42; 1024],
            &[0x42; 4095],
            &[0x42; 4096],
            &[0x42; 8000],
        ];

        for &case in cases {
            let padded = pad(case);
            assert!(padded.len() > case.len());
            let unpadded = unpad(&padded).expect("unpad should succeed");
            assert_eq!(case, unpadded.as_slice());
        }
    }

    #[test]
    fn bucket_boundaries_under_4096() {
        assert_eq!(compute_padded_len(1), 256);
        assert_eq!(compute_padded_len(256), 256);
        assert_eq!(compute_padded_len(257), 512);
        assert_eq!(compute_padded_len(512), 512);
        assert_eq!(compute_padded_len(513), 1024);
        assert_eq!(compute_padded_len(1024), 1024);
        assert_eq!(compute_padded_len(1025), 2048);
        assert_eq!(compute_padded_len(2048), 2048);
        assert_eq!(compute_padded_len(2049), 4096);
        assert_eq!(compute_padded_len(4096), 4096);
    }

    #[test]
    fn rejects_missing_delimiter() {
        let invalid = vec![0x00; 256];
        let res = unpad(&invalid);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("missing 0x80"));
    }
}
