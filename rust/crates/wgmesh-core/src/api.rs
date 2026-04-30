//! Wire types between coordinator and agents.
//!
//! These mirror the JSON encoding emitted by the original Go implementation
//! exactly, so a Rust agent can talk to a Go coordinator (and vice versa).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const HEADER_TIMESTAMP: &str = "X-Sig-Timestamp";
pub const HEADER_PUBKEY: &str = "X-Sig-Pubkey";
pub const HEADER_SIGNATURE: &str = "X-Sig-Signature";
/// ±60s skew window. Enforced by the coordinator on every signed request.
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub ssh_public_key: String,
    pub wg_public_key: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub mesh_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub hostname: String,
    pub wg_public_key: String,
    pub mesh_ip: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub listen_port: u16,
    pub last_seen: DateTime<Utc>,
}

/// Description of the coordinator's WireGuard hub. When present in `/peers`,
/// agents install it as a peer with `AllowedIPs = mesh_cidr` (the catch-all).
///
/// **No `endpoint` field on the wire.** The coord publishes only its WG
/// listen `port`; the agent derives the host from its own `coordinator`
/// URL (no need to repeat the same hostname twice in two different configs).
/// `host` is an optional override, used only when the WG hostname must
/// differ from the HTTP hostname (e.g., HTTP behind a TCP-only CDN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    pub wg_public_key: String,
    /// Optional host override. Empty string → agent derives from the
    /// `coordinator` URL it's already configured with.
    #[serde(default)]
    pub host: String,
    /// Coord's WG UDP listen port. Always populated.
    pub port: u16,
    pub mesh_ip: String,
    pub mesh_cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersResponse {
    #[serde(rename = "self_pubkey")]
    pub self_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relay: Option<Relay>,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_response_omits_relay_when_none() {
        let r = PeersResponse {
            self_pubkey: "abc".into(),
            relay: None,
            peers: vec![],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("relay"), "expected omitted relay, got {s}");
    }

    #[test]
    fn peers_response_includes_relay_when_some() {
        let r = PeersResponse {
            self_pubkey: "abc".into(),
            relay: Some(Relay {
                wg_public_key: "K".into(),
                host: String::new(),
                port: 51820,
                mesh_ip: "10.42.0.1".into(),
                mesh_cidr: "10.42.0.0/16".into(),
            }),
            peers: vec![],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"relay\""));
        assert!(s.contains("\"port\":51820"));
    }
}
