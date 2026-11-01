#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Hybrid Post-Quantum Key Encapsulation (X-Wing: X25519 + ML-KEM-768).
//!
//! Conforms to `draft-connolly-cfrg-xwing-02` and `docs/CRYPTO.md`.
//! Combines classical X25519 with post-quantum ML-KEM-768 (FIPS 203) using
//! an explicit AND combiner over HKDF-SHA-256 with domain separation.

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tn_types::TnError;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Context domain separation label for X-Wing hybrid key encapsulation.
pub const LABEL_XWING_KEM: &[u8] = b"tn/v1/kem/xwing\0";

/// Hybrid public transport key (DTK-Pub).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    /// 32-byte classical X25519 public key.
    pub x25519: [u8; 32],
    /// 1184-byte ML-KEM-768 encapsulation key (FIPS 203).
    pub ml_kem: Vec<u8>,
}

impl HybridKemPublicKey {
    /// Serializes to raw concatenated bytes: `x25519 (32B) || ml_kem (1184B)` (total 1216B).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ml_kem.len());
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.ml_kem);
        out
    }

    /// Deserializes from raw concatenated bytes: `x25519 (32B) || ml_kem (1184B)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TnError> {
        if bytes.len() != 32 + 1184 {
            return Err(TnError::Internal(
                "Invalid HybridKemPublicKey byte length".into(),
            ));
        }
        let mut x25519 = [0u8; 32];
        x25519.copy_from_slice(&bytes[..32]);
        let ml_kem = bytes[32..].to_vec();
        Ok(Self { x25519, ml_kem })
    }
}

/// Hybrid private transport key (DTK-Priv).
pub struct HybridKemPrivateKey {
    pub(crate) x25519: StaticSecret,
    pub(crate) ml_kem: DecapsulationKey<MlKem768>,
}

/// Hybrid ciphertext produced by encapsulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// 32-byte ephemeral X25519 public key.
    pub x25519_ephemeral: [u8; 32],
    /// 1088-byte ML-KEM-768 ciphertext.
    pub ml_kem_ct: Vec<u8>,
}

/// Keypair for hybrid key encapsulation.
pub struct HybridKemKeyPair {
    /// Public key for encapsulation.
    pub public_key: HybridKemPublicKey,
    /// Private key for decapsulation.
    pub private_key: HybridKemPrivateKey,
}

impl HybridKemKeyPair {
    /// Generates a fresh hybrid keypair using OS CSPRNG.
    ///
    /// # Errors
    /// Returns `TnError::Internal` if entropy generation fails.
    pub fn generate() -> Result<Self, TnError> {
        // 1. Classical X25519 keypair
        let mut x_seed = [0u8; 32];
        getrandom::getrandom(&mut x_seed)
            .map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;
        let x_priv = StaticSecret::from(x_seed);
        let x_pub = X25519PublicKey::from(&x_priv);
        x_seed.zeroize();

        // 2. Post-Quantum ML-KEM-768 keypair
        let mut ml_seed = [0u8; 64];
        getrandom::getrandom(&mut ml_seed)
            .map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;
        let ml_priv = DecapsulationKey::<MlKem768>::from_seed(ml_seed.into());
        ml_seed.zeroize();

        let ml_pub_bytes = ml_priv.encapsulation_key().to_bytes().to_vec();

        Ok(Self {
            public_key: HybridKemPublicKey {
                x25519: *x_pub.as_bytes(),
                ml_kem: ml_pub_bytes,
            },
            private_key: HybridKemPrivateKey {
                x25519: x_priv,
                ml_kem: ml_priv,
            },
        })
    }
}

/// Encapsulates a fresh 32-byte shared secret to a recipient's hybrid public key.
///
/// # Security (AND Combiner):
/// Derives shared secret from BOTH:
/// - $SS_{\text{classical}} = \text{X25519}(\text{ephemeral\_sk}, \text{recipient\_pk})$
/// - $SS_{\text{pq}} = \text{ML-KEM-768.Encapsulate}(\text{recipient\_pk})$
///
/// $SS = \text{HKDF-Extract-and-Expand}(SS_{\text{classical}} \mathbin{\Vert} SS_{\text{pq}})$
///
/// # Errors
/// Returns `TnError::Internal` if public key format is invalid.
pub fn encapsulate(
    recipient_pk: &HybridKemPublicKey,
) -> Result<([u8; 32], HybridCiphertext), TnError> {
    // 1. Classical X25519 ephemeral Diffie-Hellman
    let mut eph_seed = [0u8; 32];
    getrandom::getrandom(&mut eph_seed)
        .map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;
    let x_ephemeral = StaticSecret::from(eph_seed);
    eph_seed.zeroize();

    let x_ephemeral_pub = X25519PublicKey::from(&x_ephemeral);
    let x_recipient = X25519PublicKey::from(recipient_pk.x25519);
    let mut ss_x25519 = x_ephemeral.diffie_hellman(&x_recipient).to_bytes();

    // 2. Post-quantum ML-KEM-768 encapsulation
    if recipient_pk.ml_kem.len() != 1184 {
        return Err(TnError::Internal(
            "Invalid ML-KEM-768 public key length".into(),
        ));
    }
    let ml_ek_array = Array::try_from(recipient_pk.ml_kem.as_slice())
        .map_err(|_| TnError::Internal("Invalid ML-KEM-768 public key size".into()))?;
    let ml_ek = EncapsulationKey::<MlKem768>::new(&ml_ek_array)
        .map_err(|_| TnError::Internal("Invalid ML-KEM-768 public key".into()))?;

    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).map_err(|e| TnError::Internal(format!("Entropy failure: {e}")))?;
    let (ml_ct, ml_ss) = ml_ek.encapsulate_deterministic(&m.into());
    m.zeroize();

    let ml_ct_bytes = ml_ct.to_vec();
    let mut ss_mlkem = [0u8; 32];
    ss_mlkem.copy_from_slice(ml_ss.as_slice());

    // 3. AND Combiner: HKDF-SHA-256 over concatenated secrets
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ss_x25519);
    ikm.extend_from_slice(&ss_mlkem);

    ss_x25519.zeroize();
    ss_mlkem.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(LABEL_XWING_KEM), &ikm);
    ikm.zeroize();

    let mut info = Vec::with_capacity(32 + ml_ct_bytes.len() + 32 + recipient_pk.ml_kem.len());
    info.extend_from_slice(x_ephemeral_pub.as_bytes());
    info.extend_from_slice(&ml_ct_bytes);
    info.extend_from_slice(&recipient_pk.x25519);
    info.extend_from_slice(&recipient_pk.ml_kem);

    let mut combined_ss = [0u8; 32];
    hk.expand(&info, &mut combined_ss)
        .map_err(|e| TnError::Internal(format!("HKDF expand: {e}")))?;

    let ciphertext = HybridCiphertext {
        x25519_ephemeral: *x_ephemeral_pub.as_bytes(),
        ml_kem_ct: ml_ct_bytes,
    };

    Ok((combined_ss, ciphertext))
}

/// Decapsulates a 32-byte shared secret from a hybrid ciphertext using the private key.
///
/// # Errors
/// Returns `TnError::Internal` if ciphertext format is invalid.
pub fn decapsulate(
    private_key: &HybridKemPrivateKey,
    public_key: &HybridKemPublicKey,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], TnError> {
    // 1. Classical X25519 Diffie-Hellman
    let x_ephemeral = X25519PublicKey::from(ciphertext.x25519_ephemeral);
    let mut ss_x25519 = private_key.x25519.diffie_hellman(&x_ephemeral).to_bytes();

    // 2. Post-quantum ML-KEM-768 decapsulation
    if ciphertext.ml_kem_ct.len() != 1088 {
        return Err(TnError::Internal(
            "Invalid ML-KEM-768 ciphertext length".into(),
        ));
    }
    let ml_ct_array = Array::try_from(ciphertext.ml_kem_ct.as_slice())
        .map_err(|_| TnError::Internal("Invalid ML-KEM-768 ciphertext size".into()))?;
    let ml_ss = private_key.ml_kem.decapsulate(&ml_ct_array);
    let mut ss_mlkem = [0u8; 32];
    ss_mlkem.copy_from_slice(ml_ss.as_slice());

    // 3. AND Combiner: HKDF-SHA-256 over concatenated secrets
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ss_x25519);
    ikm.extend_from_slice(&ss_mlkem);

    ss_x25519.zeroize();
    ss_mlkem.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(LABEL_XWING_KEM), &ikm);
    ikm.zeroize();

    let mut info =
        Vec::with_capacity(32 + ciphertext.ml_kem_ct.len() + 32 + public_key.ml_kem.len());
    info.extend_from_slice(&ciphertext.x25519_ephemeral);
    info.extend_from_slice(&ciphertext.ml_kem_ct);
    info.extend_from_slice(&public_key.x25519);
    info.extend_from_slice(&public_key.ml_kem);

    let mut combined_ss = [0u8; 32];
    hk.expand(&info, &mut combined_ss)
        .map_err(|e| TnError::Internal(format!("HKDF expand: {e}")))?;

    Ok(combined_ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let keypair = HybridKemKeyPair::generate().unwrap();

        let (ss_sender, ct) = encapsulate(&keypair.public_key).unwrap();
        let ss_receiver = decapsulate(&keypair.private_key, &keypair.public_key, &ct).unwrap();

        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn test_hybrid_kem_tampered_x25519_fails() {
        let keypair = HybridKemKeyPair::generate().unwrap();
        let (ss_sender, mut ct) = encapsulate(&keypair.public_key).unwrap();

        // Tamper with classical ephemeral key
        ct.x25519_ephemeral[0] ^= 0xFF;
        let ss_receiver = decapsulate(&keypair.private_key, &keypair.public_key, &ct).unwrap();

        // Must derive completely different shared secret!
        assert_ne!(ss_sender, ss_receiver);
    }

    #[test]
    fn test_hybrid_kem_tampered_mlkem_fails() {
        let keypair = HybridKemKeyPair::generate().unwrap();
        let (ss_sender, mut ct) = encapsulate(&keypair.public_key).unwrap();

        // Tamper with post-quantum ciphertext
        ct.ml_kem_ct[0] ^= 0xFF;
        let ss_receiver = decapsulate(&keypair.private_key, &keypair.public_key, &ct).unwrap();

        // ML-KEM implicit rejection produces divergent shared secret
        assert_ne!(ss_sender, ss_receiver);
    }
}
