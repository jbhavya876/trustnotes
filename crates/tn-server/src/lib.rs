#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-server`: Untrusted sync server and transparency epoch publisher.
//!
//! Exposes:
//! - [`ServerDb`]: Relational storage layer strictly matching `docs/METADATA.md`.
//! - [`Sequencer`]: Sequences operations into per-account RFC 9162 trees and issues receipts.
//! - [`EpochPublisher`]: Builds hashed epoch trees and global transparency log checkpoints.
//! - [`Server`]: High-level API dispatcher for all `/v1/` routes.

pub mod db;
pub mod epoch_publisher;
pub mod sequencer;
pub mod service;

pub use db::ServerDb;
pub use epoch_publisher::EpochPublisher;
pub use sequencer::Sequencer;
pub use service::Server;

#[cfg(test)]
mod tests {
    use super::*;
    use tn_crypto::SigningKeys;
    use tn_oplog::{Hlc, Op};
    use tn_proto::{sign_request, AccountRegisterReq, OpSubmitReq};
    use tn_types::{Id16, Id32, OpKind};

    #[test]
    fn schema_audit() {
        // Enforce Claim C2: every table and column in SQLite must be in METADATA.md
        let db = ServerDb::in_memory().unwrap();
        db.verify_schema_conformity()
            .expect("Schema audit failed: unregistered tables or columns found!");
    }

    #[test]
    fn test_server_register_submit_and_fetch() {
        let mut server = Server::in_memory("test.trustnotes.local".to_string()).unwrap();
        let device_keys = SigningKeys::generate().unwrap();
        let device_vk = device_keys.verifying_keys();

        let account_id = Id32::from_bytes([0x11; 32]);
        let device_id = Id32::from_bytes([0x22; 32]);
        let now_ms = 1_700_000_000_000u64;

        // 1. Initial op (kind 3: DeviceAdd)
        let initial_op = Op {
            v: 1,
            account_id,
            device_id,
            lane_seq: 0,
            lane_prev: None,
            hlc: Hlc::new(now_ms, 0),
            kind: OpKind::DeviceAdd,
            object_id: Id16::from_bytes([0; 16]),
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct: vec![],
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        };

        let reg_req = AccountRegisterReq {
            account_id,
            aik_ed_pub: [1u8; 32],
            aik_pq_pub: vec![2u8; 100],
            initial_op: Some(initial_op),
            invite_token: None,
        };

        server.register_account(&reg_req, now_ms).unwrap();

        // 2. Submit second op (kind 1: Put note)
        let op2 = Op {
            v: 1,
            account_id,
            device_id,
            lane_seq: 1,
            lane_prev: Some(Id32::from_bytes([0xAA; 32])),
            hlc: Hlc::new(now_ms + 10, 0),
            kind: OpKind::Put,
            object_id: Id16::from_bytes([0x55; 16]),
            nk_wrap: Some(vec![0x77; 72]),
            nonce: [0x88; 24],
            deps: vec![],
            ct: vec![1, 2, 3, 4],
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        };

        let submit_req = OpSubmitReq {
            ops: vec![op2],
            receipt_requested: true,
        };

        let req_bytes = tn_types::cbor::encode_canonical(&submit_req).unwrap();
        let headers = sign_request(
            "POST",
            "/v1/ops",
            "",
            &req_bytes,
            device_id,
            &device_keys,
            [0x99; 16],
            now_ms + 20,
            "test.trustnotes.local",
        )
        .unwrap();

        let resp = server
            .submit_ops(&submit_req, &headers, &device_vk, now_ms + 20)
            .unwrap();
        assert_eq!(resp.accepted, 1);
        assert_eq!(resp.receipts.len(), 1);

        // Verify receipt signature
        let receipt = &resp.receipts[0];
        assert_eq!(receipt.index, 1);
        assert!(receipt.verify(&server.verifying_keys()).is_ok());

        // 3. Fetch ops
        let fetch = server.fetch_ops(&account_id, Some(0), 10).unwrap();
        assert_eq!(fetch.ops.len(), 1);
        assert_eq!(fetch.account_tree_size, 2);

        // 4. Publish epoch
        let cp = server.publish_epoch(now_ms + 60_000).unwrap();
        assert_eq!(cp.size, 1);
        assert!(server.get_checkpoint().is_some());
    }

    #[test]
    fn test_server_anti_replay_nonce() {
        let mut server = Server::in_memory("test.trustnotes.local".to_string()).unwrap();
        let device_keys = SigningKeys::generate().unwrap();
        let device_vk = device_keys.verifying_keys();

        let account_id = Id32::from_bytes([0x11; 32]);
        let device_id = Id32::from_bytes([0x22; 32]);
        let now_ms = 1_700_000_000_000u64;

        let initial_op = Op {
            v: 1,
            account_id,
            device_id,
            lane_seq: 0,
            lane_prev: None,
            hlc: Hlc::new(now_ms, 0),
            kind: OpKind::DeviceAdd,
            object_id: Id16::from_bytes([0; 16]),
            nk_wrap: None,
            nonce: [0u8; 24],
            deps: vec![],
            ct: vec![],
            sig_ed: [0u8; 64],
            sig_pq: vec![],
        };

        server
            .register_account(
                &AccountRegisterReq {
                    account_id,
                    aik_ed_pub: [1u8; 32],
                    aik_pq_pub: vec![2u8; 100],
                    initial_op: Some(initial_op),
                    invite_token: None,
                },
                now_ms,
            )
            .unwrap();

        let submit_req = OpSubmitReq {
            ops: vec![],
            receipt_requested: false,
        };
        let req_bytes = tn_types::cbor::encode_canonical(&submit_req).unwrap();
        let nonce = [0x55; 16];

        let headers = sign_request(
            "POST",
            "/v1/ops",
            "",
            &req_bytes,
            device_id,
            &device_keys,
            nonce,
            now_ms + 10,
            "test.trustnotes.local",
        )
        .unwrap();

        // First attempt succeeds
        assert!(server
            .submit_ops(&submit_req, &headers, &device_vk, now_ms + 10)
            .is_ok());

        // Replay of same nonce fails with OrderViolation
        let replay = server.submit_ops(&submit_req, &headers, &device_vk, now_ms + 10);
        assert!(matches!(replay, Err(tn_types::TnError::OrderViolation)));
    }
}
