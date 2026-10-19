//! Persisted node registry + stable mesh IP allocator.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
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
    /// Pinned IPs from config: raw ed25519 key (base64) → mesh IP.
    static_ips: RwLock<HashMap<String, String>>,
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
            static_ips: RwLock::new(HashMap::new()),
            inner: Mutex::new(state),
        };
        s.persist()?;
        Ok(s)
    }

    /// Replace the pinned-IP table. Takes effect on each node's next `upsert`.
    pub fn set_static_ips(&self, static_ips: HashMap<String, String>) {
        *self.static_ips.write().unwrap() = static_ips;
    }

    pub fn upsert(&self, ed_pub: &str, req: &api::RegisterRequest) -> Result<String, StoreError> {
        let statics = self.static_ips.read().unwrap().clone();
        let mut blocked = self.reserved.clone();
        blocked.extend(statics.values().cloned());
        let mut g = self.inner.lock().unwrap();
        let mesh_ip = match statics.get(ed_pub) {
            Some(pinned) => {
                // A reservation wins over whatever state.json says: move any
                // other holder to a fresh dynamic IP so /peers never shows
                // two nodes on one address.
                let holders: Vec<String> = g
                    .nodes
                    .iter()
                    .filter(|(k, n)| k.as_str() != ed_pub && n.mesh_ip == *pinned)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in holders {
                    let fresh = allocate_locked(&mut g, self.network, self.prefix_bits, &blocked)?;
                    if let Some(n) = g.nodes.get_mut(&k) {
                        n.mesh_ip = fresh;
                    }
                }
                pinned.clone()
            }
            None => match g.nodes.get(ed_pub) {
                // Keep a dynamic IP unless it has since been reserved.
                Some(n) if !blocked.contains(&n.mesh_ip) => n.mesh_ip.clone(),
                _ => allocate_locked(&mut g, self.network, self.prefix_bits, &blocked)?,
            },
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

    /// Apply authorization to persisted identities as well as API callers.
    pub fn authorized_peers(
        &self,
        self_ed_pub: &str,
        ttl: Duration,
        signers: &crate::signers::Signers,
    ) -> Vec<api::Peer> {
        let authorized = signers.snapshot();
        let statics = self.static_ips.read().unwrap().clone();
        let g = self.inner.lock().unwrap();
        let cutoff = Utc::now()
            - chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(0));
        let mut ip_counts = HashMap::new();
        for node in g.nodes.values() {
            *ip_counts.entry(&node.mesh_ip).or_insert(0usize) += 1;
        }
        let mut peers: Vec<_> = g
            .nodes
            .values()
            .filter(|n| {
                n.ed_pub != self_ed_pub && authorized.contains(&n.ed_pub) && n.last_seen >= cutoff
            })
            // Do not resurrect malformed or impersonated records written by
            // older coordinators. A valid registration replaces these records.
            .filter(|n| {
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                let expected = B64
                    .decode(&n.ed_pub)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .and_then(|key| wgmesh_core::keyderive::wg_pub_from_ed25519_pub(&key).ok());
                let valid_ip = n.mesh_ip.parse::<Ipv4Addr>().ok().is_some_and(|ip| {
                    let mask = if self.prefix_bits == 0 {
                        0
                    } else {
                        u32::MAX << (32 - self.prefix_bits)
                    };
                    let addr = u32::from(ip);
                    (addr & mask) == self.network
                        && addr != self.network
                        && addr != (self.network | !mask)
                        && !self.reserved.contains(&n.mesh_ip)
                        // Reserved for another key: stale until this node re-registers.
                        && statics
                            .iter()
                            .all(|(k, ip)| *ip != n.mesh_ip || *k == n.ed_pub)
                        && ip_counts.get(&n.mesh_ip) == Some(&1)
                });
                valid_ip
                    && expected.map(|k| B64.encode(k)).as_deref() == Some(n.wg_pubkey.as_str())
                    && n.listen_port != 0
                    && n.endpoints.len() <= 32
                    && n.endpoints
                        .iter()
                        .all(|ep| wgmesh_wglink::validate_endpoint(ep).is_ok())
            })
            .map(|n| api::Peer {
                hostname: n.hostname.clone(),
                wg_public_key: n.wg_pubkey.clone(),
                mesh_ip: n.mesh_ip.clone(),
                endpoints: n.endpoints.clone(),
                listen_port: n.listen_port,
                last_seen: n.last_seen,
            })
            .collect();
        peers.sort_by(|a, b| a.mesh_ip.cmp(&b.mesh_ip));
        peers
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
        let s = Store::open(path.to_str().unwrap(), Ipv4Addr::new(10, 42, 0, 0), 16, &[]).unwrap();
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
        let s = Store::open(path.to_str().unwrap(), Ipv4Addr::new(10, 42, 0, 0), 16, &[]).unwrap();
        s.upsert("a", &req()).unwrap();
        let cidr = s.mesh_ip_cidr("a").unwrap();
        assert!(cidr.ends_with("/16"));
    }

    #[test]
    fn peers_excludes_self() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(path.to_str().unwrap(), Ipv4Addr::new(10, 42, 0, 0), 16, &[]).unwrap();
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
            let s =
                Store::open(path.to_str().unwrap(), Ipv4Addr::new(10, 42, 0, 0), 16, &[]).unwrap();
            s.upsert("a", &req()).unwrap();
        }
        let s2 = Store::open(path.to_str().unwrap(), Ipv4Addr::new(10, 42, 0, 0), 16, &[]).unwrap();
        assert!(s2.mesh_ip_cidr("a").is_some());
    }
    #[test]
    fn legacy_state_filters_invalid_routes_duplicate_ips_and_excess_endpoints() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let dir = tempfile::tempdir().unwrap();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
        let raw = B64.encode(ed.as_bytes());
        let pk = ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(*ed.as_bytes())),
            "test",
        );
        let sp = dir.path().join("signers");
        std::fs::write(&sp, pk.to_openssh().unwrap()).unwrap();
        let signers = crate::signers::Signers::load(sp.to_str().unwrap()).unwrap();
        let store = Store::open(
            dir.path().join("state.json").to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &["10.42.0.1"],
        )
        .unwrap();
        let mut valid = req();
        valid.wg_public_key =
            B64.encode(wgmesh_core::keyderive::wg_pub_from_ed25519_pub(ed.as_bytes()).unwrap());
        store.upsert(&raw, &valid).unwrap();
        assert_eq!(
            store
                .authorized_peers("", Duration::from_secs(600), &signers)
                .len(),
            1
        );
        let original = store.inner.lock().unwrap().nodes[&raw].clone();
        for ip in [
            "garbage",
            "192.0.2.1",
            "10.42.0.0",
            "10.42.255.255",
            "10.42.0.1",
        ] {
            let mut node = original.clone();
            node.mesh_ip = ip.into();
            store.inner.lock().unwrap().nodes.insert(raw.clone(), node);
            assert!(
                store
                    .authorized_peers("", Duration::from_secs(600), &signers)
                    .is_empty(),
                "accepted {ip}"
            );
        }
        let mut node = original.clone();
        node.endpoints = vec!["203.0.113.1:51820".into(); 33];
        store.inner.lock().unwrap().nodes.insert(raw.clone(), node);
        assert!(store
            .authorized_peers("", Duration::from_secs(600), &signers)
            .is_empty());
        let mut g = store.inner.lock().unwrap();
        g.nodes.insert(raw, original.clone());
        g.nodes.insert("duplicate".into(), original);
        drop(g);
        assert!(store
            .authorized_peers("", Duration::from_secs(600), &signers)
            .is_empty());
    }

    fn open_with_statics(statics: &[(&str, &str)]) -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = Store::open(
            path.to_str().unwrap(),
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            &["10.42.0.1"],
        )
        .unwrap();
        s.set_static_ips(
            statics
                .iter()
                .map(|(k, ip)| ((*k).to_string(), (*ip).to_string()))
                .collect(),
        );
        (s, dir)
    }

    #[test]
    fn dynamic_allocation_skips_static_ips() {
        // Dynamic allocation starts at 10.42.0.2; pin that and the next one.
        let (s, _d) = open_with_statics(&[("pinned", "10.42.0.2"), ("pinned2", "10.42.0.3")]);
        assert_eq!(s.upsert("dyn", &req()).unwrap(), "10.42.0.4");
        assert_eq!(s.upsert("pinned", &req()).unwrap(), "10.42.0.2");
    }

    #[test]
    fn static_ip_overrides_previous_dynamic_ip() {
        let (s, _d) = open_with_statics(&[]);
        let first = s.upsert("a", &req()).unwrap();
        s.set_static_ips(HashMap::from([("a".into(), "10.42.0.50".into())]));
        assert_eq!(s.upsert("a", &req()).unwrap(), "10.42.0.50");
        assert_ne!(first, "10.42.0.50");
        assert_eq!(s.mesh_ip_cidr("a").unwrap(), "10.42.0.50/16");
        // And it is stable, not re-allocated.
        assert_eq!(s.upsert("a", &req()).unwrap(), "10.42.0.50");
    }

    #[test]
    fn static_ip_steals_from_other_node_which_gets_a_fresh_one() {
        let (s, _d) = open_with_statics(&[]);
        let taken = s.upsert("other", &req()).unwrap();
        s.set_static_ips(HashMap::from([("owner".into(), taken.clone())]));
        assert_eq!(s.upsert("owner", &req()).unwrap(), taken);
        let g = s.inner.lock().unwrap();
        let other_ip = g.nodes["other"].mesh_ip.clone();
        assert_ne!(other_ip, taken);
        assert_eq!(g.nodes["owner"].mesh_ip, taken);
        drop(g);
        // The evicted node keeps its new IP on re-register.
        assert_eq!(s.upsert("other", &req()).unwrap(), other_ip);
    }

    #[test]
    fn dynamic_node_holding_newly_reserved_ip_is_reallocated_on_register() {
        let (s, _d) = open_with_statics(&[]);
        let ip = s.upsert("dyn", &req()).unwrap();
        s.set_static_ips(HashMap::from([("absent".into(), ip.clone())]));
        let new_ip = s.upsert("dyn", &req()).unwrap();
        assert_ne!(new_ip, ip);
    }

    #[test]
    fn stale_holder_of_reserved_ip_is_not_advertised() {
        let (s, _d) = open_with_statics(&[]);
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ed.as_bytes());
        let mut r = req();
        r.wg_public_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            wgmesh_core::keyderive::wg_pub_from_ed25519_pub(ed.as_bytes()).unwrap(),
        );
        let ip = s.upsert(&key, &r).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("signers");
        let pk = ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(*ed.as_bytes())),
            "t",
        );
        std::fs::write(&sp, pk.to_openssh().unwrap()).unwrap();
        let signers = crate::signers::Signers::load(sp.to_str().unwrap()).unwrap();
        let ttl = Duration::from_secs(600);
        assert_eq!(s.authorized_peers("", ttl, &signers).len(), 1);
        s.set_static_ips(HashMap::from([("someone-else".into(), ip)]));
        assert!(s.authorized_peers("", ttl, &signers).is_empty());
    }
}
