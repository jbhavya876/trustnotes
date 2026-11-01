#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tn-adversary`: Malicious server simulator and adversarial test harness (SPEC §7).
//!
//! Implements adversary simulation drivers for security claims C1-C10 and
//! adversary scenarios S1 through S17.
//!
//! Module M2 coverage:
//! - S4: Invalid server signature rejection.
//! - S6/S9: Tree rollback and backward timestamp rejection.
//! - S8: Insufficient witness threshold rejection.
//! - S13: Fail-closed on missing checkpoint (NEVER fallback to null/cached root).
//! - S14: Consistency proof root mismatch rejection.

use tn_core::sync::SyncTransport;
use tn_crypto::VerifyingKeys;
use tn_proto::{
    AccountHeadResp, AuthHeaders, ConsistencyProofResp, OpFetchResp, OpSubmitReq, OpSubmitResp,
};
use tn_server::Server;
use tn_tlog::Checkpoint;
use tn_types::{Id32, TnError};

/// Mock adversarial transport wrapper that allows intercepting and mutating responses.
pub struct AdversarialTransport<'a> {
    pub server: &'a mut Server,
    pub device_vk: VerifyingKeys,
    pub now_ms: u64,
    /// If true, simulate checkpoint endpoint failure (S13).
    pub drop_checkpoint: bool,
    /// If Some, override checkpoint response with malicious checkpoint.
    pub forged_checkpoint: Option<Checkpoint>,
    /// If Some, override account head response with malicious head (e.g. S6 rollback).
    pub forged_head: Option<AccountHeadResp>,
    /// If Some, override consistency proof with invalid proof (S14).
    pub forged_consistency_proof: Option<ConsistencyProofResp>,
}

impl<'a> AdversarialTransport<'a> {
    pub fn new(server: &'a mut Server, device_vk: VerifyingKeys, now_ms: u64) -> Self {
        Self {
            server,
            device_vk,
            now_ms,
            drop_checkpoint: false,
            forged_checkpoint: None,
            forged_head: None,
            forged_consistency_proof: None,
        }
    }
}

impl<'a> SyncTransport for AdversarialTransport<'a> {
    fn submit_ops(
        &mut self,
        req: &OpSubmitReq,
        headers: &AuthHeaders,
    ) -> Result<OpSubmitResp, TnError> {
        self.server
            .submit_ops(req, headers, &self.device_vk, self.now_ms)
    }

    fn fetch_ops(
        &self,
        account_id: &Id32,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<OpFetchResp, TnError> {
        self.server.fetch_ops(account_id, after_index, limit)
    }

    fn get_account_head(&self, account_id: &Id32) -> Result<AccountHeadResp, TnError> {
        if let Some(head) = &self.forged_head {
            return Ok(head.clone());
        }
        self.server.get_account_head(account_id)
    }

    fn get_account_consistency_proof(
        &self,
        account_id: &Id32,
        from_size: u64,
    ) -> Result<ConsistencyProofResp, TnError> {
        if let Some(proof) = &self.forged_consistency_proof {
            return Ok(proof.clone());
        }
        self.server
            .get_account_consistency_proof(account_id, from_size)
    }

    fn get_checkpoint(&self) -> Result<Checkpoint, TnError> {
        if self.drop_checkpoint {
            return Err(TnError::Unavailable);
        }
        if let Some(cp) = &self.forged_checkpoint {
            return Ok(cp.clone());
        }
        self.server
            .get_checkpoint()
            .cloned()
            .ok_or(TnError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tn_core::{sync::SyncClient, vault::Vault};
    use tn_tlog::{Cosignature, WitnessPolicy};

    fn setup_test_env() -> (Server, WitnessPolicy, [u8; 32], [u8; 32]) {
        let server = Server::in_memory("test.adversary.origin".to_string()).unwrap();
        let w1 = [0x11u8; 32];
        let w2 = [0x22u8; 32];
        let policy = WitnessPolicy {
            threshold: 2,
            pinned_witnesses: vec![w1, w2],
            max_age_seconds: 300,
        };
        (server, policy, w1, w2)
    }

    /// Scenario S13: Checkpoint endpoint unreachable / missing.
    ///
    /// Client MUST abort sync with `TnError::Unavailable` and NEVER fall back
    /// to an unverified or cached root.
    #[test]
    fn adversary_scenario_s13_checkpoint_unavailable() {
        let (mut server, policy, _, _) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            1_700_000_000_000,
        );
        transport.drop_checkpoint = true;

        let res = client.pull_and_verify(&mut vault, &transport, 1_700_000_000_000);
        assert!(matches!(res, Err(TnError::Unavailable)));
    }

    /// Scenario S8: Witness threshold unsatisfied.
    ///
    /// Server provides a checkpoint with fewer than `k` valid cosignatures.
    /// Client MUST reject with `TnError::WitnessPolicy`.
    #[test]
    fn adversary_scenario_s8_insufficient_cosignatures() {
        let (mut server, policy, w1, _) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        let now_ms = 1_700_000_000_000u64;
        let mut cp = server.publish_epoch(now_ms).unwrap();
        // Policy requires 2 cosignatures, provide only 1
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp);

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::WitnessPolicy)));
    }

    /// Scenario S6/S9: Server attempts tree rollback.
    ///
    /// Server serves an account head smaller than local verified ops.
    /// Client MUST reject with `TnError::Rollback`.
    #[test]
    fn adversary_scenario_s6_rollback_rejected() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        // Local vault creates 2 notes
        let _ = vault.new_note("N1", "B1", vec![], None).unwrap();
        let _ = vault.new_note("N2", "B2", vec![], None).unwrap();

        let now_ms = 1_700_000_000_000u64;
        let mut cp = server.publish_epoch(now_ms).unwrap();
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        cp.cosignatures.push(Cosignature {
            witness_key_id: w2,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp);

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        // Adversary forges head with size 1 when local has 2 ops
        transport.forged_head = Some(AccountHeadResp {
            account_id: vault.account_id(),
            tree_size: 1,
            root_hash: [0xEE; 32],
        });

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::Rollback)));
    }

    /// Scenario S14: Consistency proof root mismatch.
    ///
    /// Server provides consistency proof with corrupted sibling path / forged root.
    /// Client MUST reject with `TnError::RootMismatch`.
    #[test]
    fn adversary_scenario_s14_consistency_root_mismatch() {
        let (mut server, policy, w1, w2) = setup_test_env();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let (mut vault, _) = Vault::create_new(&db_path, Some("adv-pass")).unwrap();

        // Local vault creates 1 note
        let _ = vault.new_note("N1", "B1", vec![], None).unwrap();

        let now_ms = 1_700_000_000_000u64;
        let mut cp = server.publish_epoch(now_ms).unwrap();
        cp.cosignatures.push(Cosignature {
            witness_key_id: w1,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        cp.cosignatures.push(Cosignature {
            witness_key_id: w2,
            timestamp_ms: now_ms,
            sig_ed: [0u8; 64],
        });
        server.set_latest_checkpoint(cp);

        let mut client = SyncClient::new(
            "test.adversary.origin".to_string(),
            server.verifying_keys(),
            policy,
        );

        let mut transport = AdversarialTransport::new(
            &mut server,
            vault.signing_keys_ref().verifying_keys(),
            now_ms,
        );

        // Server claims size is 5 but provides bogus consistency path
        transport.forged_head = Some(AccountHeadResp {
            account_id: vault.account_id(),
            tree_size: 5,
            root_hash: [0x55; 32],
        });
        transport.forged_consistency_proof = Some(ConsistencyProofResp {
            old_size: 1,
            new_size: 5,
            path: vec![[0xAA; 32], [0xBB; 32]],
        });

        let res = client.pull_and_verify(&mut vault, &transport, now_ms + 100);
        assert!(matches!(res, Err(TnError::RootMismatch)));
    }
}
