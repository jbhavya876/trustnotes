#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]
//! `tn-crypto`: Cryptographic primitive wrappers for `TrustNotes`.
//!
//! # Security Invariants
//!
//! - Every key is a strongly-typed newtype. Raw `[u8; 32]` never crosses a module boundary.
//! - Nonces are generated inside the AEAD wrapper. Callers cannot supply them.
//! - Secret types: no `Clone` unless required, no `Debug` disclosure, `Drop` zeroizes.
//! - The hybrid signature rule is AND: both Ed25519 and ML-DSA-65 must verify.
//!   Either failing rejects. Never accept either-or.
//! - Domain Separation: Every operation carries a unique `tn/v1/` context label.
//! - Known-Answer Tests (KATs) for all primitives.

pub mod aead;
pub mod kat;
pub mod kdf;
pub mod keys;
pub mod labels;
pub mod padding;
pub mod recovery;
pub mod signature;

pub use aead::{
    open_local, open_note_payload, seal_local, seal_note_payload, unwrap_note_key, wrap_note_key,
};
pub use kdf::{
    derive_account_id, derive_account_root, derive_aik_ed_seed, derive_aik_pq_seed,
    derive_device_id, derive_lsk_from_passphrase, derive_vault_key,
};
pub use keys::{AccountRoot, LocalStorageKey, NoteKey, RecoveryKey, VaultKey};
pub use padding::{pad, unpad};
pub use recovery::{decode_recovery_key, encode_recovery_key, entropy_to_words, BIP39_WORDLIST};
pub use signature::{HybridSignature, SigningKeys, VerifyingKeys};
