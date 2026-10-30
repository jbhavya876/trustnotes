#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
//! `tn-core`: Client core library for trustnotes.
//!
//! Encompasses the local encrypted vault, per-column AEAD storage, local full-text search,
//! the client sync engine, and the fail-closed verification pipeline.
//!
//! # M0 Status
//!
//! Skeleton crate. Local storage and note CRUD arrive in M1; sync engine in M2;
//! verification pipeline in M3.

use tn_types::TnError;

/// Client vault state.
pub struct Vault {
    /// In-memory vault status.
    _placeholder: (),
}

impl Vault {
    /// Initialize an empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self { _placeholder: () }
    }

    /// Unlock the vault with the local storage key.
    ///
    /// # Errors
    ///
    /// Returns [`TnError::Internal`] until M1.
    pub fn unlock(&mut self, _key: &[u8; 32]) -> Result<(), TnError> {
        Err(TnError::Internal("not implemented — M1".to_string()))
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_new() {
        let _ = Vault::new();
        assert_eq!(1 + 1, 2);
    }
}
