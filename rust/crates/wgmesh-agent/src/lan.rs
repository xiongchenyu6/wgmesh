//! Enumerate non-loopback, non-link-local IPv4/v6 addresses on UP interfaces
//! to advertise as LAN candidate endpoints.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

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
        if skip_ifaces.contains(&ia.name) {
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
}
