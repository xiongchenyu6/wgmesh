//! Coordinator's WireGuard hub: every agent appears as a peer with
//! `AllowedIPs = <agent.mesh>/32`. Kernel IP forwarding + `wg0` relay traffic
//! between agents that haven't established a direct shortcut.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::sync::Arc;
use tracing::info;
use wgmesh_core::{api, keyderive};
use wgmesh_wglink::{Manager, PeerSpec};

use crate::config::Config;
use crate::store::Store;

pub struct Relay {
    cfg: Arc<Config>,
    store: Arc<Store>,
    wg_pub: [u8; 32],
    wm: Manager,
}

impl Relay {
    pub fn start(cfg: Arc<Config>, store: Arc<Store>) -> Result<Self> {
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

    /// Sync the relay's wg0 peer set to the current store contents.
    pub fn reconcile(&self) -> Result<()> {
        let peers = self.store.peers("", self.cfg.peer_ttl);
        let mut specs = Vec::with_capacity(peers.len());
        for p in &peers {
            if p.wg_public_key.is_empty() || p.mesh_ip.is_empty() {
                continue;
            }
            specs.push(PeerSpec {
                pub_key_b64: p.wg_public_key.clone(),
                endpoint: p.endpoints.first().cloned(),
                allowed_ips: vec![format!("{}/32", p.mesh_ip)],
                keepalive_secs: Some(25),
            });
        }
        self.wm.replace_peers(&specs).context("relay reconcile")?;
        info!(peers = specs.len(), "relay synced");
        Ok(())
    }
}
