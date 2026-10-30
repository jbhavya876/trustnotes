#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Strongly typed key wrappers.
//!
//! Enforces the rule: **Never pass a raw `[u8; 32]` across a module boundary.**
//! All private key material implements `ZeroizeOnDrop` and refuses contents disclosure in `Debug`.

use std::fmt;

/// 256-bit entropy derived from or encoded to the 24-word BIP-39 Recovery Key.
pub struct RecoveryKey(pub(crate) [u8; 32]);

impl RecoveryKey {
    /// Create a new `RecoveryKey` from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose inner bytes temporarily for cryptographic derivation.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryKey([REDACTED])")
    }
}

/// The Account Root (AR) derived via HKDF(RK, "tn/v1/account-root").
pub struct AccountRoot(pub(crate) [u8; 32]);

impl AccountRoot {
    /// Create an `AccountRoot` from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose bytes for child key derivation.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for AccountRoot {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for AccountRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountRoot([REDACTED])")
    }
}

/// The Vault Key (VK) derived via HKDF(AR, "tn/v1/vault-key").
pub struct VaultKey(pub(crate) [u8; 32]);

impl VaultKey {
    /// Create a `VaultKey` from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose bytes for wrapping or unwrapping Note Keys.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultKey([REDACTED])")
    }
}

/// The symmetric Note Key (NK) for decrypting an individual note's payload.
pub struct NoteKey(pub(crate) [u8; 32]);

impl NoteKey {
    /// Create a `NoteKey` from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose bytes for AEAD encryption/decryption of the note payload.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for NoteKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for NoteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoteKey([REDACTED])")
    }
}

/// Local Storage Key (LSK) for encrypting local SQLite database columns.
pub struct LocalStorageKey(pub(crate) [u8; 32]);

impl LocalStorageKey {
    /// Create a `LocalStorageKey` from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose bytes for SQLite column encryption.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for LocalStorageKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for LocalStorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalStorageKey([REDACTED])")
    }
}
