//! Enumerate non-loopback, non-link-local IPv4/v6 addresses on UP interfaces
//! to advertise as LAN candidate endpoints.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

/// True if `name` matches a skip entry. An entry ending in `*` is a prefix
/// match (`br-*` skips `br-1a2b3c`); any other entry must match exactly.
pub fn is_skipped(name: &str, skip: &HashSet<String>) -> bool {
    skip.iter().any(|entry| match entry.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => entry == name,
    })
}

pub fn local_endpoints(listen_port: u16, skip_ifaces: &HashSet<String>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return out,
    };
    for ia in ifaces {
        if ia.is_loopback() {
            continue;
        }
        if is_skipped(&ia.name, skip_ifaces) {
            continue;
        }
        let ip = ia.ip();
        if !share_worthy(ip) {
            continue;
        }
        out.push(SocketAddr::new(ip, listen_port));
    }
    out
}

fn share_worthy(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        IpAddr::V6(v6) => {
            // IPv6 link-local prefix fe80::/10.
            let seg = v6.segments()[0];
            (seg & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_worthy_filters_link_local_v4() {
        assert!(!share_worthy("169.254.5.5".parse().unwrap()));
        assert!(!share_worthy("127.0.0.1".parse().unwrap()));
        assert!(share_worthy("10.0.0.5".parse().unwrap()));
        assert!(share_worthy("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn share_worthy_filters_link_local_v6() {
        assert!(!share_worthy("fe80::1".parse().unwrap()));
        assert!(share_worthy("2001:db8::1".parse().unwrap()));
    }

    fn set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn skip_exact_names_only_match_exactly() {
        let skip = set(&["lo", "wg0"]);
        assert!(is_skipped("wg0", &skip));
        assert!(!is_skipped("wg01", &skip));
        assert!(!is_skipped("xwg0", &skip));
    }

    #[test]
    fn skip_trailing_star_is_prefix_match() {
        let skip = set(&["br-*", "veth*"]);
        assert!(is_skipped("br-1a2b3c4d5e6f", &skip));
        assert!(is_skipped("veth9f3a", &skip));
        assert!(is_skipped("veth", &skip));
        assert!(!is_skipped("br0", &skip));
        assert!(!is_skipped("eth0", &skip));
    }

    #[test]
    fn skip_star_only_special_at_end() {
        let skip = set(&["a*b"]);
        assert!(!is_skipped("axb", &skip));
        assert!(is_skipped("a*b", &skip));
    }
}
