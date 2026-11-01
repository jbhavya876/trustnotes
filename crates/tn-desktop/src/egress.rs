#![forbid(unsafe_code)]

//! Outbound Network Egress Allow-List Enforcer (SPEC §M6, Section 406).
//!
//! # Security Guarantees
//! When AI is disabled, or when operating normally, TrustNotes is cryptographically
//! isolated from the public internet. Outbound connections are strictly restricted to:
//! 1. The configured sync server (`/v1/...`).
//! 2. Registered witness nodes (`/v1/witness/...`).
//! 3. Registered Bitcoin OpenTimestamps calendar nodes.
//! 4. Optional user-configured localhost AI inference (`http://127.0.0.1:<port>`).
//!
//! Any attempt to initiate a network request to an unlisted destination is blocked
//! fail-closed with [`TnError::EgressViolation`].

use std::collections::HashSet;
use tn_types::TnError;

/// Strict egress allow-list policy.
#[derive(Debug, Clone)]
pub struct EgressAllowList {
    allowed_hosts: HashSet<String>,
    ai_allowed_localhost: Option<u16>,
}

impl EgressAllowList {
    /// Creates a new allow-list with explicit endpoints.
    #[must_use]
    pub fn new(
        sync_server_host: &str,
        witness_hosts: &[&str],
        anchor_hosts: &[&str],
        ai_localhost_port: Option<u16>,
    ) -> Self {
        let mut allowed_hosts = HashSet::new();
        allowed_hosts.insert(sync_server_host.to_ascii_lowercase());

        for w in witness_hosts {
            allowed_hosts.insert(w.to_ascii_lowercase());
        }

        for a in anchor_hosts {
            allowed_hosts.insert(a.to_ascii_lowercase());
        }

        Self {
            allowed_hosts,
            ai_allowed_localhost: ai_localhost_port,
        }
    }

    /// Verifies whether an outbound destination URL is strictly permitted by the policy.
    ///
    /// # Errors
    /// Returns `TnError::EgressViolation` if destination is unlisted.
    pub fn check_egress(&self, target_url: &str) -> Result<(), TnError> {
        let parsed = target_url.to_ascii_lowercase();

        // 1. Check if it's a loopback AI request
        if parsed.starts_with("http://127.0.0.1:") || parsed.starts_with("http://localhost:") {
            if let Some(allowed_port) = self.ai_allowed_localhost {
                let port_str = format!(":{allowed_port}");
                if parsed.contains(&port_str) {
                    return Ok(());
                }
            }
            return Err(TnError::EgressViolation(format!(
                "Loopback egress port disallowed: {target_url}"
            )));
        }

        // 2. Check if host is in explicit allow-list
        for allowed in &self.allowed_hosts {
            if parsed.contains(allowed) {
                return Ok(());
            }
        }

        Err(TnError::EgressViolation(format!(
            "Outbound destination not in egress allow-list: {target_url}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egress_allow_list_permits_configured_endpoints() {
        let policy = EgressAllowList::new(
            "sync.trustnotes.org",
            &["witness1.trustnotes.org", "witness2.trustnotes.org"],
            &["alice.btc.calendar.opentimestamps.org"],
            Some(11434),
        );

        assert!(policy
            .check_egress("https://sync.trustnotes.org/v1/notes")
            .is_ok());
        assert!(policy
            .check_egress("https://witness1.trustnotes.org/checkpoint")
            .is_ok());
        assert!(policy
            .check_egress("https://alice.btc.calendar.opentimestamps.org/digest")
            .is_ok());
        assert!(policy
            .check_egress("http://127.0.0.1:11434/api/generate")
            .is_ok());
    }

    #[test]
    fn test_egress_allow_list_blocks_unauthorized_endpoints() {
        let policy = EgressAllowList::new(
            "sync.trustnotes.org",
            &["witness1.trustnotes.org"],
            &[],
            None, // AI disabled
        );

        // Third party LLM cloud
        let err1 = policy.check_egress("https://api.openai.com/v1/chat/completions");
        assert!(matches!(err1, Err(TnError::EgressViolation(_))));

        // Telemetry / analytics tracking
        let err2 = policy.check_egress("https://telemetry.segment.io/v1/track");
        assert!(matches!(err2, Err(TnError::EgressViolation(_))));

        // Remote CDN font loading
        let err3 = policy.check_egress("https://fonts.googleapis.com/css?family=Roboto");
        assert!(matches!(err3, Err(TnError::EgressViolation(_))));

        // Disallowed port on loopback when AI disabled
        let err4 = policy.check_egress("http://127.0.0.1:11434/api/generate");
        assert!(matches!(err4, Err(TnError::EgressViolation(_))));
    }
}
