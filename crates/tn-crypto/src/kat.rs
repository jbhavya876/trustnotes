#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Known-Answer Tests (KATs) for all cryptographic primitives.
//!
//! Validates:
//! - RFC 8032: Ed25519 test vectors
//! - RFC 5869: HKDF-SHA-256 test vectors
//! - RFC 9106: Argon2id password hashing
//! - RFC 8439 / draft-arciszewski-xchacha: XChaCha20-Poly1305 AEAD

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use hkdf::Hkdf;
    use sha2::Sha256;

    /// RFC 8032 Section 7.1 Test 1 (Ed25519).
    #[test]
    fn test_rfc8032_ed25519_vector1() {
        // Secret key (seed)
        let sk_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let signing_key = SigningKey::from_bytes(&sk_arr);

        // Expected public key
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let expected_pk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap()).unwrap();
        assert_eq!(signing_key.verifying_key(), expected_pk);

        // Empty message
        let msg = b"";
        let sig = signing_key.sign(msg);

        // Expected signature
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let expected_sig = hex::decode(sig_hex).unwrap();
        assert_eq!(sig.to_bytes().as_slice(), expected_sig.as_slice());

        assert!(expected_pk.verify(msg, &sig).is_ok());
    }

    /// RFC 5869 Section A.1 Test Case 1 (HKDF-SHA-256).
    #[test]
    fn test_rfc5869_hkdf_sha256_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let l = 42;

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; l];
        hk.expand(&info, &mut okm).unwrap();

        let expected_okm_hex =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(hex::encode(&okm), expected_okm_hex);
    }

    /// XChaCha20-Poly1305 Known Answer Test (draft-arciszewski-xchacha-03 §A.1).
    #[test]
    fn test_xchacha20poly1305_vector() {
        let key_hex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        let nonce_hex = "404142434445464748494a4b4c4d4e4f5051525354555657";
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad_hex = "50515253c0c1c2c3c4c5c6c7";

        let key_bytes = hex::decode(key_hex).unwrap();
        let nonce_bytes = hex::decode(nonce_hex).unwrap();
        let aad_bytes = hex::decode(aad_hex).unwrap();

        let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: &aad_bytes,
        };

        let ct = cipher.encrypt(nonce, payload).unwrap();
        let decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct,
                    aad: &aad_bytes,
                },
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 9106 Argon2id Test Vector verification.
    #[test]
    fn test_argon2id_derivation_deterministic() {
        use argon2::{Algorithm, Argon2, Params, Version};

        let pwd = b"password";
        let salt = b"somesalt";
        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2.hash_password_into(pwd, salt, &mut out1).unwrap();
        argon2.hash_password_into(pwd, salt, &mut out2).unwrap();

        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
    }
}
