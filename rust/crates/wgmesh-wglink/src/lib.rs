//! Kernel WireGuard interface management via `wg(8)` and `ip(8)`.
//!
//! We deliberately shell out instead of going through netlink directly: it
//! keeps the binary tiny, mirrors what the original Go code did internally
//! (via wgctrl), and the reconcile rate is once-per-30s so process spawn
//! overhead is irrelevant.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum WgError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{cmd}: exit {code}: {stderr}")]
    Exit {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error("parse `wg show` output: {0}")]
    ParseShow(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

/// One peer entry to install/update on the interface.
///
/// `allowed_ips` may be empty — in PROBING state we want the peer in the
/// device (so the kernel attempts handshakes) but with zero CIDRs claimed,
/// so cryptokey-routing doesn't black-hole traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    pub pub_key_b64: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keepalive_secs: Option<u32>,
}

/// Observed runtime state for one peer of the device.
#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub pub_key_b64: String,
    pub endpoint: Option<String>,
    /// Unix timestamp of last handshake (0 = never).
    pub last_handshake_unix: i64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Owns one `wg<N>` interface name. All operations are stateless w.r.t. the
/// struct itself; cloning is fine.
#[derive(Debug, Clone)]
pub struct Manager {
    pub iface: String,
}

impl Manager {
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }

    /// Create the WG interface if absent and bring it up.
    pub fn ensure_link(&self) -> Result<(), WgError> {
        if !self.link_exists()? {
            run(
                "ip",
                &["link", "add", &self.iface, "type", "wireguard"],
            )?;
        }
        run("ip", &["link", "set", &self.iface, "up"])?;
        Ok(())
    }

    fn link_exists(&self) -> Result<bool, WgError> {
        let out = Command::new("ip")
            .args(["link", "show", &self.iface])
            .output()?;
        Ok(out.status.success())
    }

    /// Add `cidr` to the interface; ignore if already present.
    pub fn ensure_address(&self, cidr: &str) -> Result<(), WgError> {
        let out = Command::new("ip")
            .args(["addr", "add", cidr, "dev", &self.iface])
            .output()?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("exists") || stderr.contains("file exists") {
            return Ok(());
        }
        Err(WgError::Exit {
            cmd: format!("ip addr add {cidr} dev {}", self.iface),
            code: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Ensure `cidr` is the only IPv4 address on the interface.
    pub fn replace_mesh_address(&self, cidr: &str) -> Result<(), WgError> {
        self.ensure_address(cidr)?;
        let out = Command::new("ip")
            .args(["-o", "-4", "addr", "show", "dev", &self.iface])
            .output()?;
        if !out.status.success() {
            return Ok(());
        }
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let mut fields = line.split_whitespace();
            let mut present: Option<&str> = None;
            while let Some(f) = fields.next() {
                if f == "inet" {
                    present = fields.next();
                    break;
                }
            }
            if let Some(p) = present {
                if p != cidr {
                    let _ = Command::new("ip")
                        .args(["addr", "del", p, "dev", &self.iface])
                        .output();
                }
            }
        }
        Ok(())
    }

    /// Set the device's private key + listen port. Idempotent.
    pub fn configure(&self, priv_key: &[u8; 32], listen_port: u16) -> Result<(), WgError> {
        // wg(8) reads the private key from a file path; write to a tempfile
        // with 0600 mode and unlink after.
        let path = tempfile_with_mode(B64.encode(priv_key).as_bytes(), 0o600)?;
        let res = run(
            "wg",
            &[
                "set",
                &self.iface,
                "listen-port",
                &listen_port.to_string(),
                "private-key",
                path.to_string_lossy().as_ref(),
            ],
        );
        let _ = std::fs::remove_file(&path);
        res
    }

    /// Atomically replace the device's full peer set with `peers`.
    pub fn replace_peers(&self, peers: &[PeerSpec]) -> Result<(), WgError> {
        let conf = render_syncconf(peers);
        debug!(iface = %self.iface, peers = peers.len(), "syncconf");
        let path = tempfile_with_mode(conf.as_bytes(), 0o600)?;
        let res = run(
            "wg",
            &[
                "syncconf",
                &self.iface,
                path.to_string_lossy().as_ref(),
            ],
        );
        let _ = std::fs::remove_file(&path);
        res
    }

    /// Read peer state from `wg show <iface> dump`.
    pub fn handshakes(&self) -> Result<HashMap<String, PeerInfo>, WgError> {
        let out = Command::new("wg")
            .args(["show", &self.iface, "dump"])
            .output()?;
        if !out.status.success() {
            return Err(WgError::Exit {
                cmd: format!("wg show {} dump", self.iface),
                code: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        parse_wg_dump(&String::from_utf8_lossy(&out.stdout))
    }

    /// Read the device's listen port (0 if unconfigured).
    pub fn listen_port(&self) -> Result<u16, WgError> {
        let out = Command::new("wg")
            .args(["show", &self.iface, "listen-port"])
            .output()?;
        if !out.status.success() {
            return Err(WgError::Exit {
                cmd: format!("wg show {} listen-port", self.iface),
                code: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| WgError::InvalidValue(e.to_string()))
    }
}

/// Best-effort root check, used to fail fast with a friendly message.
pub fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

/// Format a wg syncconf-compatible configuration. We omit `[Interface]`
/// because we configure the device-level state separately via `wg set`;
/// syncconf accepts a peer-only file and replaces the peer table from it.
pub fn render_syncconf(peers: &[PeerSpec]) -> String {
    let mut out = String::new();
    for p in peers {
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", p.pub_key_b64));
        // AllowedIPs may be empty (PROBING). wg(8) accepts an empty list.
        out.push_str(&format!("AllowedIPs = {}\n", p.allowed_ips.join(", ")));
        if let Some(ep) = &p.endpoint {
            out.push_str(&format!("Endpoint = {ep}\n"));
        }
        if let Some(k) = p.keepalive_secs {
            out.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
        out.push('\n');
    }
    out
}

/// Parse the tab-separated output of `wg show <iface> dump`.
/// First line: `<priv> <pub> <listen-port> <fwmark>` (device info).
/// Subsequent lines: `<peer-pub> <psk> <endpoint> <allowed-ips> <latest-hs> <rx> <tx> <keepalive>`.
fn parse_wg_dump(s: &str) -> Result<HashMap<String, PeerInfo>, WgError> {
    let mut out = HashMap::new();
    for (i, line) in s.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if i == 0 {
            // Device-info line — skip.
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 {
            warn!(line, "wg dump peer row has fewer than 7 fields; skipping");
            continue;
        }
        let pub_key_b64 = fields[0].to_string();
        let endpoint = match fields[2] {
            "(none)" | "" => None,
            s => Some(s.to_string()),
        };
        let last_handshake_unix: i64 =
            fields[4].parse().unwrap_or(0);
        let rx_bytes: u64 = fields[5].parse().unwrap_or(0);
        let tx_bytes: u64 = fields[6].parse().unwrap_or(0);
        out.insert(
            pub_key_b64.clone(),
            PeerInfo {
                pub_key_b64,
                endpoint,
                last_handshake_unix,
                rx_bytes,
                tx_bytes,
            },
        );
    }
    Ok(out)
}

fn run(bin: &str, args: &[&str]) -> Result<(), WgError> {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    Err(WgError::Exit {
        cmd: format!("{bin} {}", args.join(" ")),
        code: out.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Write `data` to a freshly-created temp file with the given mode bits, return its path.
fn tempfile_with_mode(data: &[u8], mode: u32) -> Result<PathBuf, std::io::Error> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        .as_nanos();
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wgmesh-{pid}-{nanos}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(&path, perms)?;
        f.write_all(data)?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_empty_allowed_ips_for_probing_peer() {
        let peers = vec![PeerSpec {
            pub_key_b64: "AAAA".into(),
            endpoint: Some("1.2.3.4:51820".into()),
            allowed_ips: vec![],
            keepalive_secs: Some(25),
        }];
        let cfg = render_syncconf(&peers);
        assert!(cfg.contains("[Peer]"));
        assert!(cfg.contains("PublicKey = AAAA"));
        assert!(cfg.contains("AllowedIPs = \n"), "expected empty AllowedIPs, got:\n{cfg}");
        assert!(cfg.contains("Endpoint = 1.2.3.4:51820"));
        assert!(cfg.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn renders_multiple_allowed_ips() {
        let peers = vec![PeerSpec {
            pub_key_b64: "Z".into(),
            endpoint: None,
            allowed_ips: vec!["10.42.0.5/32".into(), "10.42.0.6/32".into()],
            keepalive_secs: None,
        }];
        let cfg = render_syncconf(&peers);
        assert!(cfg.contains("AllowedIPs = 10.42.0.5/32, 10.42.0.6/32"));
        assert!(!cfg.contains("Endpoint"));
        assert!(!cfg.contains("PersistentKeepalive"));
    }

    #[test]
    fn parses_wg_dump_with_peer() {
        // device line + one peer line, tab-separated as wg(8) emits.
        let s = "PRIV\tDEVPUB\t51820\toff\n\
                 PEERPUB\t(none)\t1.2.3.4:51820\t10.42.0.5/32\t1700000000\t1024\t2048\t25\n";
        let m = parse_wg_dump(s).unwrap();
        assert_eq!(m.len(), 1);
        let p = m.get("PEERPUB").unwrap();
        assert_eq!(p.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(p.last_handshake_unix, 1_700_000_000);
        assert_eq!(p.rx_bytes, 1024);
        assert_eq!(p.tx_bytes, 2048);
    }

    #[test]
    fn parses_wg_dump_with_no_endpoint_and_zero_handshake() {
        let s = "PRIV\tDEVPUB\t51820\toff\n\
                 PEERPUB\t(none)\t(none)\t10.42.0.5/32\t0\t0\t0\toff\n";
        let m = parse_wg_dump(s).unwrap();
        let p = m.get("PEERPUB").unwrap();
        assert!(p.endpoint.is_none());
        assert_eq!(p.last_handshake_unix, 0);
    }
}
