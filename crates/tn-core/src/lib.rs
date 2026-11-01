#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]
//! `tn-core`: Client core library for `TrustNotes`.
//!
//! Encompasses:
//! - Local encrypted vault with SQLite and per-column AEAD (`storage`)
//! - In-memory inverted full-text search index (`search`)
//! - Client sync engine & fail-closed verification pipeline (`sync`)
//! - High-level note CRUD and fail-closed verification pipeline (`vault`)

pub mod search;
pub mod storage;
pub mod sync;
pub mod vault;

pub use search::SearchIndex;
pub use storage::Storage;
pub use sync::{SyncClient, SyncReport};
pub use vault::{NoteDetail, NoteSummary, Vault, VerificationReport};
