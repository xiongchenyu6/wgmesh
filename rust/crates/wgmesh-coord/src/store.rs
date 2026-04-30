//! Persisted node registry + stable mesh IP allocator.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use wgmesh_core::api;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse state: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("mesh CIDR exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub ed_pub: String,
    pub hostname: String,
    pub wg_pubkey: String,
    pub mesh_ip: String,
    pub endpoints: Vec<String>,
    pub listen_port: u16,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    next_host_bits: u32,
    #[serde(default)]
    nodes: HashMap<String, Node>,
}

pub struct Store {
    path: PathBuf,
    network: u32,
    prefix_bits: u8,
    reserved: HashSet<String>,
    inner: Mutex<StateFile>,
}

impl Store {
    pub fn open(
        path: &str,
        network: Ipv4Addr,
        prefix_bits: u8,
        reserved: &[&str],
    ) -> Result<Self, StoreError> {
        let mut state = StateFile {
            next_host_bits: 1,
            nodes: HashMap::new(),
        };
        match std::fs::read(path) {
            Ok(data) if !data.trim_ascii().is_empty() => {
                state = serde_json::from_slice(&data)?;
                if state.next_host_bits == 0 {
                    state.next_host_bits = 1;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::Io(e)),
        }
        let s = Self {
            path: PathBuf::from(path),
            network: u32::from(network),
            prefix_bits,
            reserved: reserved.iter().map(|s| (*s).to_string()).collect(),
            inner: Mutex::new(state),
        };
        s.persist()?;
        Ok(s)
    }

    pub fn upsert(
        &self,
        ed_pub: &str,
        req: &api::RegisterRequest,
    ) -> Result<String, StoreError> {
        let mut g = self.inner.lock().unwrap();
        let mesh_ip = match g.nodes.get(ed_pub) {
            Some(n) => n.mesh_ip.clone(),
            None => allocate_locked(
                &mut g,
                self.network,
                self.prefix_bits,
                &self.reserved,
            )?,
        };
        let node = Node {
            ed_pub: ed_pub.to_string(),
            hostname: req.hostname.clone(),
            wg_pubkey: req.wg_public_key.clone(),
            mesh_ip: mesh_ip.clone(),
            endpoints: req.endpoints.clone(),
            listen_port: req.listen_port,
            last_seen: Utc::now(),
        };
        g.nodes.insert(ed_pub.to_string(), node);
        let snapshot = serialize(&g)?;
        drop(g);
        write_atomic(&self.path, &snapshot)?;
        Ok(mesh_ip)
    }

    /// Returns peers within `ttl` of now, excluding `self_ed_pub` (pass `""` to include all).
    pub fn peers(&self, self_ed_pub: &str, ttl: Duration) -> Vec<api::Peer> {
        let g = self.inner.lock().unwrap();
        let cutoff = Utc::now()
            - chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(0));
        let mut out: Vec<api::Peer> = g
            .nodes
            .iter()
            .filter(|(k, _)| k.as_str() != self_ed_pub)
            .filter(|(_, n)| n.last_seen >= cutoff)
            .map(|(_, n)| api::Peer {
                hostname: n.hostname.clone(),
                wg_public_key: n.wg_pubkey.clone(),
                mesh_ip: n.mesh_ip.clone(),
                endpoints: n.endpoints.clone(),
                listen_port: n.listen_port,
                last_seen: n.last_seen,
            })
            .collect();
        out.sort_by(|a, b| a.mesh_ip.cmp(&b.mesh_ip));
        out
    }

    /// `<mesh_ip>/<prefix_bits>` for an existing node, or `None`.
    pub fn mesh_ip_cidr(&self, ed_pub: &str) -> Option<String> {
        let g = self.inner.lock().unwrap();
        g.nodes
            .get(ed_pub)
            .filter(|n| !n.mesh_ip.is_empty())
            .map(|n| format!("{}/{}", n.mesh_ip, self.prefix_bits))
    }

    fn persist(&self) -> Result<(), StoreError> {
        let g = self.inner.lock().unwrap();
        let snapshot = serialize(&g)?;
        drop(g);
        write_atomic(&self.path, &snapshot)
    }
}

fn allocate_locked(
    state: &mut StateFile,
    network: u32,
    prefix_bits: u8,
    reserved: &HashSet<String>,
) -> Result<String, StoreError> {
    let mut taken: HashSet<String> = state.nodes.values().map(|n| n.mesh_ip.clone()).collect();
    for ip in reserved {
        taken.insert(ip.clone());
    }
    let host_bits = 32 - prefix_bits as u32;
    let max_host: u32 = if host_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << host_bits).saturating_sub(1)
    };
    let mut off = state.next_host_bits;
    while off < max_host {
        let ip_str = Ipv4Addr::from(network + off).to_string();
        if taken.contains(&ip_str) {
            off += 1;
            state.next_host_bits = off;
            continue;
        }
        state.next_host_bits = off + 1;
        return Ok(ip_str);
    }
    Err(StoreError::Exhausted)
}

fn serialize(state: &StateFile) -> Result<Vec<u8>, StoreError> {
    Ok(serde_json::to_vec_pretty(state)?)
}

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("tmp.{pid}.{nanos}"));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> api::RegisterRequest {
        api::RegisterRequest {
            hostname: "h".into(),
            ssh_public_key: "ignored".into(),
            wg_public_key: "Wpub".into(),
            endpoints: vec!["1.2.3.4:51820".into()],
            listen_port: 51820,
        }
    }

    #[test]
    fn allocates_stable_ip_across_reregister() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &[],
        )
        .unwrap();
        let ip1 = s.upsert("eda", &req()).unwrap();
        let ip2 = s.upsert("eda", &req()).unwrap();
        assert_eq!(ip1, ip2);
        assert!(ip1.starts_with("10.42.0."));
    }

    #[test]
    fn skips_reserved_ip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &["10.42.0.1"],
        )
        .unwrap();
        let ip = s.upsert("a", &req()).unwrap();
        assert_ne!(ip, "10.42.0.1");
    }

    #[test]
    fn mesh_ip_cidr_includes_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &[],
        )
        .unwrap();
        s.upsert("a", &req()).unwrap();
        let cidr = s.mesh_ip_cidr("a").unwrap();
        assert!(cidr.ends_with("/16"));
    }

    #[test]
    fn peers_excludes_self() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &[],
        )
        .unwrap();
        s.upsert("a", &req()).unwrap();
        s.upsert("b", &req()).unwrap();
        let p = s.peers("a", Duration::from_secs(600));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn state_persists_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let s = Store::open(
                path.to_str().unwrap(),
                Ipv4Addr::new(10, 42, 0, 0),
                16,
                &[],
            )
            .unwrap();
            s.upsert("a", &req()).unwrap();
        }
        let s2 = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &[],
        )
        .unwrap();
        assert!(s2.mesh_ip_cidr("a").is_some());
    }
}
