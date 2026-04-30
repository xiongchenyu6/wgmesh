//! Main agent reconcile loop.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};
use wgmesh_core::{api, keyderive, stun};
use wgmesh_wglink::{self, Manager};

use crate::config::AgentConfig;
use crate::coord_client::CoordClient;
use crate::lan;
use crate::probe::ProbeManager;

pub fn run(cfg: AgentConfig) -> Result<()> {
    if !wgmesh_wglink::is_root() {
        bail!("wgmesh-agent needs CAP_NET_ADMIN (run as root or via systemd AmbientCapabilities)");
    }

    let id = keyderive::identity_from_ssh_file(&cfg.ssh_key)?;
    info!(wg_pub = %B64.encode(id.wg_pub), "derived WG identity");

    let wm = Manager::new(&cfg.interface);
    wm.ensure_link()?;
    wm.configure(&id.wg_priv, cfg.listen_port)?;
    info!(iface = %cfg.interface, port = cfg.listen_port, "wg interface up");

    let cc = CoordClient::new(&cfg.coordinator, &cfg.ssh_key)?;
    let wg_pub_b64 = B64.encode(id.wg_pub);

    let hostname = cfg
        .hostname
        .clone()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(read_hostname_or_unknown);

    let mut probe = ProbeManager::new();
    let mut current_mesh_cidr = String::new();

    loop {
        if let Err(e) = iterate(
            &cfg,
            &cc,
            &wm,
            &wg_pub_b64,
            &hostname,
            &mut probe,
            &mut current_mesh_cidr,
        ) {
            error!("iterate: {e}");
        }
        std::thread::sleep(Duration::from_secs(cfg.poll_secs));
    }
}

fn iterate(
    cfg: &AgentConfig,
    cc: &CoordClient,
    wm: &Manager,
    wg_pub_b64: &str,
    hostname: &str,
    probe: &mut ProbeManager,
    current_mesh_cidr: &mut String,
) -> Result<()> {
    // 1. Discover endpoints.
    let mut endpoints: Vec<String> = Vec::new();
    if !cfg.stun_server.is_empty() {
        match stun_on_port(&cfg.stun_server, cfg.listen_port) {
            Ok(addr) => {
                info!("STUN: public endpoint {addr}");
                endpoints.push(addr.to_string());
            }
            Err(e) => warn!("STUN failed (continuing): {e}"),
        }
    }
    if cfg.include_lan {
        let mut skip: HashSet<String> = std::iter::once(cfg.interface.clone()).collect();
        skip.extend(cfg.skip_iface.iter().cloned());
        for ap in lan::local_endpoints(cfg.listen_port, &skip) {
            let s = ap.to_string();
            if !endpoints.contains(&s) {
                endpoints.push(s);
            }
        }
    }
    endpoints.sort();

    // 2. Register.
    let resp = cc.register(&api::RegisterRequest {
        hostname: hostname.to_string(),
        ssh_public_key: cc.pub_line().to_string(),
        wg_public_key: wg_pub_b64.to_string(),
        endpoints,
        listen_port: cfg.listen_port,
    })?;
    if !resp.mesh_ip.is_empty() && resp.mesh_ip != *current_mesh_cidr {
        info!(mesh_ip = %resp.mesh_ip, iface = %cfg.interface, "assigning mesh IP");
        wm.replace_mesh_address(&resp.mesh_ip)?;
        *current_mesh_cidr = resp.mesh_ip.clone();
    }

    // 3. Fetch peers + relay info.
    let pr = cc.peers()?;

    // 4. Read kernel handshake state.
    let hs = wm.handshakes()?;

    // 5. Drive state machine.
    let now = SystemTime::now();
    let (specs, summary) = probe.reconcile(&pr.peers, pr.relay.as_ref(), &hs, now);
    wm.replace_peers(&specs)?;
    info!(
        relay = summary.has_relay,
        direct = summary.direct,
        probing = summary.probing,
        relaying = summary.relayed,
        total = pr.peers.len(),
        "synced"
    );
    Ok(())
}

/// Try to bind the WG listen port for STUN; if that fails (kernel WG is
/// already holding it), fall back to an ephemeral port. Mirrors the Go
/// implementation's behavior.
fn stun_on_port(server: &str, port: u16) -> Result<SocketAddr> {
    match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(sock) => {
            let addr = stun::discover_with_socket(server, &sock, Duration::from_secs(5))?;
            Ok(addr)
        }
        Err(_) => {
            let addr = stun::discover(server, Duration::from_secs(5))?;
            Ok(addr)
        }
    }
}

fn read_hostname_or_unknown() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
