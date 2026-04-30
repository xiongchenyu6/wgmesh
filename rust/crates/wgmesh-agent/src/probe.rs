//! Probe-promote-demote state machine, mirroring `internal/agent/probe.go`.
//!
//! Per-peer lifecycle:
//!   `Unknown` → `Probing` (in wg0 with empty AllowedIPs) → `Direct` (`/32`)
//!   `Direct` → `Relay` (removed from wg0; traffic falls to coord's `/16`)
//!   `Relay` → `Probing` (after exponential backoff)
//!
//! All time arithmetic is parameterized via `now: SystemTime` so tests can
//! advance the clock deterministically.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};
use wgmesh_core::api;
use wgmesh_wglink::{PeerInfo, PeerSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    Unknown,
    /// Peer is in wg0 with empty AllowedIPs; awaiting handshake.
    Probing,
    /// Peer is in wg0 with `peer.mesh/32` AllowedIPs.
    Direct,
    /// Peer is **not** in wg0; traffic flows through coord's `/16`.
    Relay,
}

impl ProbeState {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeState::Unknown => "UNKNOWN",
            ProbeState::Probing => "PROBING",
            ProbeState::Direct => "DIRECT",
            ProbeState::Relay => "RELAY",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tunables {
    pub probe_window: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub backoff_multiplier: f64,
    pub direct_stale_after: Duration,
    pub keepalive: Duration,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            probe_window: Duration::from_secs(60),
            initial_backoff: Duration::from_secs(5 * 60),
            max_backoff: Duration::from_secs(30 * 60),
            backoff_multiplier: 2.0,
            direct_stale_after: Duration::from_secs(5 * 60),
            keepalive: Duration::from_secs(25),
        }
    }
}

#[derive(Debug, Clone)]
struct PeerEntry {
    pub_b64: String,
    mesh_ip: String,
    endpoints: Vec<String>,
    hostname: String,
    state: ProbeState,
    probing_since: SystemTime,
    last_handshake: Option<SystemTime>,
    backoff: Duration,
    next_retry: Option<SystemTime>,
}

pub struct ProbeManager {
    pub tunables: Tunables,
    peers: HashMap<String, PeerEntry>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileSummary {
    pub has_relay: bool,
    pub probing: usize,
    pub direct: usize,
    pub relayed: usize,
}

impl Default for ProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeManager {
    pub fn new() -> Self {
        Self {
            tunables: Tunables::default(),
            peers: HashMap::new(),
        }
    }

    /// Update the state machine and return the desired wg0 peer set.
    pub fn reconcile(
        &mut self,
        peers: &[api::Peer],
        relay: Option<&api::Relay>,
        handshakes: &HashMap<String, PeerInfo>,
        now: SystemTime,
    ) -> (Vec<PeerSpec>, ReconcileSummary) {
        // 1. Sync map keys with current peer set.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for p in peers {
            if p.wg_public_key.is_empty() || p.mesh_ip.is_empty() {
                continue;
            }
            seen.insert(p.wg_public_key.clone());
            let entry = self.peers.entry(p.wg_public_key.clone()).or_insert_with(|| {
                info!(
                    hostname = %p.hostname,
                    mesh = %p.mesh_ip,
                    "new peer → PROBING"
                );
                PeerEntry {
                    pub_b64: p.wg_public_key.clone(),
                    mesh_ip: String::new(),
                    endpoints: vec![],
                    hostname: String::new(),
                    state: ProbeState::Probing,
                    probing_since: now,
                    last_handshake: None,
                    backoff: self.tunables.initial_backoff,
                    next_retry: None,
                }
            });
            entry.mesh_ip = p.mesh_ip.clone();
            entry.endpoints = p.endpoints.clone();
            entry.hostname = p.hostname.clone();
        }
        let drop_keys: Vec<String> = self
            .peers
            .keys()
            .filter(|k| !seen.contains(*k))
            .cloned()
            .collect();
        for k in drop_keys {
            if let Some(e) = self.peers.remove(&k) {
                info!(hostname = %e.hostname, "dropping vanished peer");
            }
        }

        // 2. Apply transitions.
        for e in self.peers.values_mut() {
            // Refresh observed handshake.
            if let Some(info) = handshakes.get(&e.pub_b64) {
                if let Some(observed) = unix_to_systemtime(info.last_handshake_unix) {
                    if e.last_handshake.map_or(true, |prev| observed > prev) {
                        e.last_handshake = Some(observed);
                    }
                }
            }
            match e.state {
                ProbeState::Probing => {
                    if let Some(hs) = e.last_handshake {
                        if let Ok(age) = now.duration_since(hs) {
                            if age < self.tunables.probe_window {
                                e.state = ProbeState::Direct;
                                e.backoff = self.tunables.initial_backoff;
                                info!(
                                    hostname = %e.hostname,
                                    age_s = age.as_secs(),
                                    "PROBING → DIRECT"
                                );
                                continue;
                            }
                        }
                    }
                    if let Ok(elapsed) = now.duration_since(e.probing_since) {
                        if elapsed > self.tunables.probe_window {
                            e.state = ProbeState::Relay;
                            e.next_retry = Some(now + e.backoff);
                            info!(
                                hostname = %e.hostname,
                                next_retry_s = e.backoff.as_secs(),
                                "PROBING → RELAY"
                            );
                        }
                    }
                }
                ProbeState::Direct => {
                    if let Some(hs) = e.last_handshake {
                        if let Ok(age) = now.duration_since(hs) {
                            if age > self.tunables.direct_stale_after {
                                e.state = ProbeState::Relay;
                                e.next_retry = Some(now + e.backoff);
                                info!(
                                    hostname = %e.hostname,
                                    stale_s = age.as_secs(),
                                    "DIRECT → RELAY"
                                );
                            }
                        }
                    }
                }
                ProbeState::Relay => {
                    if let Some(retry) = e.next_retry {
                        if now > retry {
                            e.state = ProbeState::Probing;
                            e.probing_since = now;
                            let grown = duration_mul_f64(e.backoff, self.tunables.backoff_multiplier);
                            e.backoff = grown.min(self.tunables.max_backoff);
                            info!(
                                hostname = %e.hostname,
                                next_backoff_s = e.backoff.as_secs(),
                                "RELAY → PROBING"
                            );
                        }
                    }
                }
                ProbeState::Unknown => {
                    // Newly-created entries land in Probing; Unknown is a fallback.
                    e.state = ProbeState::Probing;
                    e.probing_since = now;
                }
            }
        }

        // 3. Build wg0 peer spec list.
        let mut specs: Vec<PeerSpec> = Vec::new();
        let mut summary = ReconcileSummary::default();

        if let Some(r) = relay {
            if !r.wg_public_key.is_empty() && !r.mesh_cidr.is_empty() {
                specs.push(PeerSpec {
                    pub_key_b64: r.wg_public_key.clone(),
                    endpoint: if r.endpoint.is_empty() {
                        None
                    } else {
                        Some(r.endpoint.clone())
                    },
                    allowed_ips: vec![r.mesh_cidr.clone()],
                    keepalive_secs: Some(self.tunables.keepalive.as_secs() as u32),
                });
                summary.has_relay = true;
            } else {
                debug!("relay info missing fields; skipping");
            }
        }

        let mut keys: Vec<&String> = self.peers.keys().collect();
        keys.sort();
        for k in keys {
            let e = &self.peers[k];
            match e.state {
                ProbeState::Probing => {
                    summary.probing += 1;
                    let endpoint = e.endpoints.first().cloned();
                    if endpoint.is_none() {
                        // Can't probe without an endpoint.
                        continue;
                    }
                    specs.push(PeerSpec {
                        pub_key_b64: e.pub_b64.clone(),
                        endpoint,
                        allowed_ips: vec![],
                        keepalive_secs: Some(self.tunables.keepalive.as_secs() as u32),
                    });
                }
                ProbeState::Direct => {
                    summary.direct += 1;
                    specs.push(PeerSpec {
                        pub_key_b64: e.pub_b64.clone(),
                        endpoint: e.endpoints.first().cloned(),
                        allowed_ips: vec![format!("{}/32", e.mesh_ip)],
                        keepalive_secs: Some(self.tunables.keepalive.as_secs() as u32),
                    });
                }
                ProbeState::Relay => {
                    summary.relayed += 1;
                    // Not added to wg0; falls through coord's /16 catch-all.
                }
                ProbeState::Unknown => {}
            }
        }
        (specs, summary)
    }

    #[cfg(test)]
    pub(crate) fn entry_state(&self, pub_b64: &str) -> Option<ProbeState> {
        self.peers.get(pub_b64).map(|e| e.state)
    }

    #[cfg(test)]
    pub(crate) fn entry_backoff(&self, pub_b64: &str) -> Option<Duration> {
        self.peers.get(pub_b64).map(|e| e.backoff)
    }

    #[cfg(test)]
    pub(crate) fn entry_next_retry(&self, pub_b64: &str) -> Option<SystemTime> {
        self.peers.get(pub_b64).and_then(|e| e.next_retry)
    }

    #[cfg(test)]
    pub(crate) fn has_entry(&self, pub_b64: &str) -> bool {
        self.peers.contains_key(pub_b64)
    }
}

fn unix_to_systemtime(secs: i64) -> Option<SystemTime> {
    if secs <= 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

fn duration_mul_f64(d: Duration, m: f64) -> Duration {
    let secs = d.as_secs_f64() * m;
    if !secs.is_finite() || secs < 0.0 {
        return d;
    }
    Duration::from_secs_f64(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn fake_relay() -> api::Relay {
        api::Relay {
            wg_public_key: "RELAY-PUB".into(),
            endpoint: "203.0.113.1:51820".into(),
            mesh_ip: "10.42.0.1".into(),
            mesh_cidr: "10.42.0.0/16".into(),
        }
    }

    fn peer(pub_b64: &str) -> api::Peer {
        api::Peer {
            hostname: "n".into(),
            wg_public_key: pub_b64.into(),
            mesh_ip: "10.42.0.5".into(),
            endpoints: vec!["1.2.3.4:51820".into()],
            listen_port: 51820,
            last_seen: Utc.timestamp_opt(0, 0).unwrap(),
        }
    }

    fn unix(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn find<'a>(specs: &'a [PeerSpec], pub_b64: &str) -> Option<&'a PeerSpec> {
        specs.iter().find(|s| s.pub_key_b64 == pub_b64)
    }

    #[test]
    fn new_peer_starts_probing_with_empty_allowed_ips() {
        let mut pm = ProbeManager::new();
        let (specs, sum) = pm.reconcile(
            &[peer("A")],
            Some(&fake_relay()),
            &HashMap::new(),
            unix(1_000_000),
        );
        assert_eq!(sum.probing, 1);
        assert_eq!(sum.direct, 0);
        assert_eq!(sum.relayed, 0);
        let s = find(&specs, "A").expect("peer absent from specs while PROBING");
        assert!(
            s.allowed_ips.is_empty(),
            "PROBING peer must have empty AllowedIPs, got {:?}",
            s.allowed_ips
        );
        assert!(s.endpoint.is_some());
    }

    #[test]
    fn probing_promoted_to_direct_on_handshake() {
        let mut pm = ProbeManager::new();
        let t0 = unix(1_000_000);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t0);

        let mut hs = HashMap::new();
        hs.insert(
            "A".to_string(),
            PeerInfo {
                pub_key_b64: "A".into(),
                last_handshake_unix: 1_000_008,
                ..Default::default()
            },
        );
        let t1 = unix(1_000_010);
        let (specs, sum) = pm.reconcile(&[peer("A")], Some(&fake_relay()), &hs, t1);
        assert_eq!(sum.direct, 1);
        assert_eq!(sum.probing, 0);
        let s = find(&specs, "A").expect("DIRECT peer missing from specs");
        assert_eq!(s.allowed_ips, vec!["10.42.0.5/32".to_string()]);
    }

    #[test]
    fn probing_demoted_to_relay_on_timeout() {
        let mut pm = ProbeManager::new();
        let t0 = unix(1_000_000);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t0);
        let t1 = t0 + 2 * pm.tunables.probe_window;
        let (specs, sum) =
            pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t1);
        assert_eq!(sum.relayed, 1);
        assert_eq!(sum.probing, 0);
        assert!(find(&specs, "A").is_none(), "RELAY peer must NOT be in wg0 specs");
        assert!(sum.has_relay);
    }

    #[test]
    fn relay_returns_to_probing_with_grown_backoff() {
        let mut pm = ProbeManager::new();
        let t0 = unix(1_000_000);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t0);
        let t1 = t0 + 2 * pm.tunables.probe_window;
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t1);
        assert_eq!(pm.entry_state("A"), Some(ProbeState::Relay));
        let first_backoff = pm.entry_backoff("A").unwrap();

        let retry_at = pm.entry_next_retry("A").unwrap();
        let t2 = retry_at + Duration::from_secs(1);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t2);
        assert_eq!(pm.entry_state("A"), Some(ProbeState::Probing));
        let new_backoff = pm.entry_backoff("A").unwrap();
        assert!(
            new_backoff > first_backoff,
            "backoff should have grown from {first_backoff:?}, got {new_backoff:?}"
        );
    }

    #[test]
    fn direct_demoted_to_relay_when_handshake_stale() {
        let mut pm = ProbeManager::new();
        let t0 = unix(1_000_000);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t0);
        let mut hs = HashMap::new();
        hs.insert(
            "A".to_string(),
            PeerInfo {
                pub_key_b64: "A".into(),
                last_handshake_unix: 1_000_001,
                ..Default::default()
            },
        );
        pm.reconcile(
            &[peer("A")],
            Some(&fake_relay()),
            &hs,
            t0 + Duration::from_secs(2),
        );
        assert_eq!(pm.entry_state("A"), Some(ProbeState::Direct));

        let t1 = t0 + pm.tunables.direct_stale_after + Duration::from_secs(60);
        let (specs, sum) = pm.reconcile(&[peer("A")], Some(&fake_relay()), &hs, t1);
        assert_eq!(sum.relayed, 1);
        assert!(find(&specs, "A").is_none(), "demoted peer must not be in wg0");
    }

    #[test]
    fn vanished_peer_is_dropped() {
        let mut pm = ProbeManager::new();
        let t0 = unix(1_000_000);
        pm.reconcile(&[peer("A")], Some(&fake_relay()), &HashMap::new(), t0);
        assert!(pm.has_entry("A"));
        pm.reconcile(&[], Some(&fake_relay()), &HashMap::new(), t0 + Duration::from_secs(1));
        assert!(!pm.has_entry("A"));
    }

    #[test]
    fn relay_always_speced_with_mesh_cidr() {
        let mut pm = ProbeManager::new();
        let (specs, sum) = pm.reconcile(&[], Some(&fake_relay()), &HashMap::new(), unix(1_000_000));
        assert!(sum.has_relay);
        assert_eq!(specs.len(), 1, "expected 1 spec (relay), got {}", specs.len());
        assert_eq!(specs[0].allowed_ips, vec!["10.42.0.0/16".to_string()]);
    }
}
