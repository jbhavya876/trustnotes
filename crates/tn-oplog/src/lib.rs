#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::pedantic,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::similar_names
)]
//! `tn-oplog`: Account operation log — the append-only, CRDT-structured operation journal.
//!
//! Each account maintains a per-device op log that is authenticated, sequenced,
//! and eventually merged into a total-order account tree by the server.

pub mod conflict;
pub mod hlc;
pub mod lane;
pub mod op;

pub use conflict::{ConflictStatus, NoteDagTracker};
pub use hlc::Hlc;
pub use lane::{DeviceLaneTracker, LaneRegistry};
pub use op::{compute_ct_hash, compute_op_aad, compute_op_id, Op, OpHeader, Payload};
