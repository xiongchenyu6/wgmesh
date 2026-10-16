//! Coordinator's WireGuard hub: every agent appears as a peer with
//! `AllowedIPs = <agent.mesh>/32`. Kernel IP forwarding + `wg0` relay traffic
//! between agents that haven't established a direct shortcut.

use crate::signers::Signers;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;
use wgmesh_core::{api, keyderive};
use wgmesh_wglink::PeerInfo;
use wgmesh_wglink::{Manager, PeerSpec};

use crate::config::Config;
use crate::store::Store;

pub struct Relay {
    cfg: Arc<Config>,
    store: Arc<Store>,
    wg_pub: [u8; 32],
    wm: Manager,
    signers: Signers,
    reconcile_lock: Mutex<()>,
}

impl Relay {
    pub fn start(cfg: Arc<Config>, store: Arc<Store>, signers: Signers) -> Result<Self> {
        let id = keyderive::identity_from_ssh_file(&cfg.wg_ssh_key)
            .with_context(|| format!("derive coord WG key from {}", cfg.wg_ssh_key))?;
        let wm = Manager::new(&cfg.wg_interface);
        wm.ensure_link()
            .with_context(|| format!("ensure link {}", cfg.wg_interface))?;
        wm.configure(&id.wg_priv, cfg.wg_listen_port)
            .context("configure coord WG")?;
        let cidr = format!("{}/{}", cfg.wg_mesh_ip, cfg.prefix_bits);
        wm.replace_mesh_address(&cidr)
            .with_context(|| format!("assign coord mesh ip {cidr}"))?;
        info!(
            iface = %cfg.wg_interface,
            pubkey = %B64.encode(id.wg_pub),
            mesh = %cidr,
            port = cfg.wg_listen_port,
            host_override = %cfg.wg_endpoint_host,
            "coord WG hub up"
        );
        let r = Self {
            cfg,
            store,
            wg_pub: id.wg_pub,
            wm,
            signers,
            reconcile_lock: Mutex::new(()),
        };
        r.reconcile()?;
        Ok(r)
    }

    /// Build a `Relay` description for inclusion in `/peers` responses.
    /// `host` is the operator's optional override; empty means agents fall
    /// back to deriving the host from their own `coordinator` URL.
    pub fn info(&self) -> api::Relay {
        api::Relay {
            wg_public_key: B64.encode(self.wg_pub),
            host: self.cfg.wg_endpoint_host.clone(),
            port: self.cfg.wg_listen_port,
            mesh_ip: self.cfg.wg_mesh_ip.clone(),
            mesh_cidr: self.cfg.mesh_cidr.clone(),
        }
    }

    pub fn observed_endpoints(&self) -> Result<HashMap<String, PeerInfo>> {
        Ok(self.wm.handshakes()?)
    }

    /// Sync the relay's wg0 peer set to the current store contents.
    pub fn reconcile(&self) -> Result<()> {
        // Serialize snapshots and kernel writes, including revocation cleanup.
        let _guard = self.reconcile_lock.lock().unwrap();
        let peers = self
            .store
            .authorized_peers("", self.cfg.peer_ttl, &self.signers);
        let mut specs = Vec::with_capacity(peers.len());
        for p in &peers {
            if p.wg_public_key.is_empty() || p.mesh_ip.is_empty() {
                continue;
            }
            specs.push(PeerSpec {
                pub_key_b64: p.wg_public_key.clone(),
                // Agents initiate towards our public hub. Leave their endpoint
                // to authenticated WG roaming rather than overwrite it with
                // an advertised LAN/STUN candidate every thirty seconds.
                endpoint: None,
                allowed_ips: vec![format!("{}/32", p.mesh_ip)],
                keepalive_secs: Some(25),
            });
        }
        self.wm.replace_peers(&specs).context("relay reconcile")?;
        info!(peers = specs.len(), "relay synced");
        Ok(())
    }
}

/// A completed handshake authenticates this endpoint as the real WG socket.
/// Endpoint-dependent NATs can still require relay fallback.
pub fn add_observed_endpoints(peers: &mut [api::Peer], observed: &HashMap<String, PeerInfo>) {
    for peer in peers {
        if let Some(info) = observed.get(&peer.wg_public_key) {
            if info.last_handshake_unix <= 0 {
                continue;
            }
            if let Some(ep) = &info.endpoint {
                if wgmesh_wglink::validate_endpoint(ep).is_ok() && !peer.endpoints.contains(ep) {
                    peer.endpoints.push(ep.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publishes_only_authenticated_numeric_wg_endpoints_without_duplicates() {
        let mut peers = vec![api::Peer {
            hostname: "a".into(),
            wg_public_key: "A".into(),
            mesh_ip: "10.42.0.2".into(),
            endpoints: vec!["192.168.1.2:51820".into()],
            listen_port: 51820,
            last_seen: chrono::Utc::now(),
        }];
        let mut observed = HashMap::from([(
            "A".into(),
            PeerInfo {
                endpoint: Some("203.0.113.2:61234".into()),
                last_handshake_unix: 0,
                ..Default::default()
            },
        )]);
        add_observed_endpoints(&mut peers, &observed);
        assert_eq!(peers[0].endpoints.len(), 1);
        observed.get_mut("A").unwrap().last_handshake_unix = 1;
        add_observed_endpoints(&mut peers, &observed);
        add_observed_endpoints(&mut peers, &observed);
        assert_eq!(
            peers[0].endpoints,
            ["192.168.1.2:51820", "203.0.113.2:61234"]
        );
        observed.get_mut("A").unwrap().endpoint =
            Some("203.0.113.2:61234\nAllowedIPs = 0.0.0.0/0".into());
        add_observed_endpoints(&mut peers, &observed);
        assert_eq!(peers[0].endpoints.len(), 2);
    }
}
