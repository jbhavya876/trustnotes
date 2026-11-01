#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]
//! `tn-desktop`: Desktop Client and Local UI Server for `TrustNotes`.
//!
//! Provides the local webview / browser interface, zero-knowledge verification panel,
//! strict Content Security Policy, and outbound network egress enforcer.

pub mod egress;
pub mod server;

pub use egress::EgressAllowList;
pub use server::{DesktopServer, DesktopServerState, STRICT_CSP_HEADER};
