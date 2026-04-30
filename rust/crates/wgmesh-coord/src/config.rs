//! Coordinator JSON config, with the same defaulting rules as the Go original.
//!
//! Notably: `relay_enabled` defaults to **true** when absent. We use
//! `Option<bool>` so we can distinguish "user wrote false" from "user omitted".

use serde::Deserialize;
use std::net::Ipv4Addr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse config: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("mesh_cidr is required")]
    MissingMeshCidr,
    #[error("mesh_cidr {0} is not a valid IPv4 CIDR")]
    InvalidMeshCidr(String),
    #[error("state_path is required")]
    MissingStatePath,
    #[error("authorized_signers is required")]
    MissingAuthorizedSigners,
    #[error("relay_endpoint is required when relay_enabled (host:port reachable from agents)")]
    RelayMissingEndpoint,
    #[error("relay_mesh_ip {0} is not a valid IPv4 inside mesh_cidr")]
    InvalidRelayMeshIp(String),
}

#[derive(Debug, Deserialize)]
struct Raw {
    listen_addr: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    mesh_cidr: Option<String>,
    state_path: Option<String>,
    authorized_signers: Option<String>,
    peer_ttl_seconds: Option<i64>,
    relay_enabled: Option<bool>,
    relay_ssh_key: Option<String>,
    relay_interface: Option<String>,
    relay_listen_port: Option<u16>,
    relay_endpoint: Option<String>,
    relay_mesh_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub mesh_cidr: String,
    pub state_path: String,
    pub authorized_signers: String,
    pub peer_ttl: Duration,

    pub relay_enabled: bool,
    pub relay_ssh_key: String,
    pub relay_interface: String,
    pub relay_listen_port: u16,
    pub relay_endpoint: String,
    pub relay_mesh_ip: String,

    /// Network address of `mesh_cidr`, masked. Used by Store for allocation.
    pub network_addr: Ipv4Addr,
    /// Prefix bits of `mesh_cidr`.
    pub prefix_bits: u8,
}

impl Config {
    /// Normalize listen-addr. `:8443` (Go shorthand) → `0.0.0.0:8443`.
    pub fn listen_addr_normalized(&self) -> String {
        if let Some(rest) = self.listen_addr.strip_prefix(':') {
            format!("0.0.0.0:{rest}")
        } else {
            self.listen_addr.clone()
        }
    }
}

pub fn load(path: &str) -> Result<Config, ConfigError> {
    let data = std::fs::read(path)?;
    let raw: Raw = serde_json::from_slice(&data)?;
    from_raw(raw)
}

fn from_raw(raw: Raw) -> Result<Config, ConfigError> {
    let mesh_cidr = raw.mesh_cidr.ok_or(ConfigError::MissingMeshCidr)?;
    let state_path = raw.state_path.ok_or(ConfigError::MissingStatePath)?;
    let authorized_signers = raw
        .authorized_signers
        .ok_or(ConfigError::MissingAuthorizedSigners)?;

    let (network_addr, prefix_bits) = parse_ipv4_cidr(&mesh_cidr)
        .ok_or_else(|| ConfigError::InvalidMeshCidr(mesh_cidr.clone()))?;

    let peer_ttl_secs = raw.peer_ttl_seconds.filter(|&v| v > 0).unwrap_or(600);
    let peer_ttl = Duration::from_secs(peer_ttl_secs as u64);

    // Default-true semantics: only false if user explicitly wrote `"relay_enabled": false`.
    let relay_enabled = raw.relay_enabled.unwrap_or(true);

    let relay_ssh_key = raw
        .relay_ssh_key
        .unwrap_or_else(|| "/etc/ssh/ssh_host_ed25519_key".into());
    let relay_interface = raw.relay_interface.unwrap_or_else(|| "wg0".into());
    let relay_listen_port = raw.relay_listen_port.unwrap_or(51820);
    let relay_endpoint = raw.relay_endpoint.unwrap_or_default();
    let relay_mesh_ip = match raw.relay_mesh_ip {
        Some(s) => {
            let ip: Ipv4Addr = s
                .parse()
                .map_err(|_| ConfigError::InvalidRelayMeshIp(s.clone()))?;
            if !ipv4_in_cidr(ip, network_addr, prefix_bits) {
                return Err(ConfigError::InvalidRelayMeshIp(s));
            }
            s
        }
        None => {
            // First usable IP: network + 1.
            let n = u32::from(network_addr) + 1;
            Ipv4Addr::from(n).to_string()
        }
    };

    if relay_enabled && relay_endpoint.is_empty() {
        return Err(ConfigError::RelayMissingEndpoint);
    }

    Ok(Config {
        listen_addr: raw.listen_addr.unwrap_or_else(|| ":8443".into()),
        tls_cert: raw.tls_cert.filter(|s| !s.is_empty()),
        tls_key: raw.tls_key.filter(|s| !s.is_empty()),
        mesh_cidr,
        state_path,
        authorized_signers,
        peer_ttl,
        relay_enabled,
        relay_ssh_key,
        relay_interface,
        relay_listen_port,
        relay_endpoint,
        relay_mesh_ip,
        network_addr,
        prefix_bits,
    })
}

/// Parse `"10.42.0.0/16"` into (network address, prefix bits).
pub fn parse_ipv4_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, bits) = s.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask = if bits == 0 { 0 } else { (!0u32) << (32 - bits) };
    let net = Ipv4Addr::from(u32::from(ip) & mask);
    Some((net, bits))
}

pub fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, bits: u8) -> bool {
    let mask = if bits == 0 { 0 } else { (!0u32) << (32 - bits) };
    (u32::from(ip) & mask) == u32::from(network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_masks_correctly() {
        let (net, bits) = parse_ipv4_cidr("10.42.5.7/16").unwrap();
        assert_eq!(net, Ipv4Addr::new(10, 42, 0, 0));
        assert_eq!(bits, 16);
    }

    #[test]
    fn relay_default_true_when_absent() {
        let raw: Raw = serde_json::from_str(
            r#"{"mesh_cidr":"10.42.0.0/16","state_path":"/tmp/s","authorized_signers":"/tmp/a","relay_endpoint":"x:1"}"#,
        )
        .unwrap();
        let cfg = from_raw(raw).unwrap();
        assert!(cfg.relay_enabled);
    }

    #[test]
    fn relay_false_when_explicit() {
        let raw: Raw = serde_json::from_str(
            r#"{"mesh_cidr":"10.42.0.0/16","state_path":"/tmp/s","authorized_signers":"/tmp/a","relay_enabled":false}"#,
        )
        .unwrap();
        let cfg = from_raw(raw).unwrap();
        assert!(!cfg.relay_enabled);
    }

    #[test]
    fn relay_endpoint_required_when_enabled() {
        let raw: Raw = serde_json::from_str(
            r#"{"mesh_cidr":"10.42.0.0/16","state_path":"/tmp/s","authorized_signers":"/tmp/a"}"#,
        )
        .unwrap();
        let r = from_raw(raw);
        assert!(matches!(r, Err(ConfigError::RelayMissingEndpoint)));
    }

    #[test]
    fn default_relay_mesh_ip_is_first_usable() {
        let raw: Raw = serde_json::from_str(
            r#"{"mesh_cidr":"10.42.0.0/16","state_path":"/tmp/s","authorized_signers":"/tmp/a","relay_endpoint":"x:1"}"#,
        )
        .unwrap();
        let cfg = from_raw(raw).unwrap();
        assert_eq!(cfg.relay_mesh_ip, "10.42.0.1");
    }

    #[test]
    fn listen_addr_shorthand_normalizes() {
        let raw: Raw = serde_json::from_str(
            r#"{"mesh_cidr":"10.42.0.0/16","state_path":"/tmp/s","authorized_signers":"/tmp/a","relay_enabled":false,"listen_addr":":8443"}"#,
        )
        .unwrap();
        let cfg = from_raw(raw).unwrap();
        assert_eq!(cfg.listen_addr_normalized(), "0.0.0.0:8443");
    }
}
