//! Minimal RFC 5389 STUN client: only Binding Request / Binding Success
//! Response with XOR-MAPPED-ADDRESS parsing. Enough for NAT discovery against
//! coturn; no auth, no TLS, no RFC 5780 extensions.

use rand::RngCore;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use thiserror::Error;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_MAPPED_ADDR: u16 = 0x0001;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("resolve {0}: no addresses")]
    Resolve(String),
    #[error("stun: response too short")]
    ShortResponse,
    #[error("stun: bad magic cookie")]
    BadMagic,
    #[error("stun: txid mismatch")]
    TxidMismatch,
    #[error("stun: unexpected message type 0x{0:04x}")]
    UnexpectedType(u16),
    #[error("stun: truncated attribute")]
    TruncatedAttribute,
    #[error("stun: unknown address family 0x{0:02x}")]
    UnknownFamily(u8),
    #[error("stun: no XOR-MAPPED-ADDRESS in response")]
    NoMappedAddress,
}

/// Send a STUN binding request to `server` using the supplied UDP socket and
/// return the discovered public address. Caller is responsible for binding the
/// socket to the WireGuard listen port (so the reflexive mapping matches).
pub fn discover_with_socket(
    server: &str,
    sock: &UdpSocket,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let raddr = server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| StunError::Resolve(server.to_string()))?;

    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    let (req, tx_id) = build_binding_request();
    sock.send_to(&req, raddr)?;

    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf)?;
    parse_binding_response(&buf[..n], tx_id)
}

/// Convenience helper that opens an ephemeral UDP socket. The reflexive
/// mapping discovered this way is per-socket — useful for sanity checks but
/// not for advertising as the WireGuard endpoint.
pub fn discover(server: &str, timeout: Duration) -> Result<SocketAddr, StunError> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    discover_with_socket(server, &sock, timeout)
}

fn build_binding_request() -> ([u8; 20], [u8; 12]) {
    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut tx_id);

    let mut hdr = [0u8; 20];
    hdr[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    hdr[2..4].copy_from_slice(&0u16.to_be_bytes()); // length 0
    hdr[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    hdr[8..20].copy_from_slice(&tx_id);
    (hdr, tx_id)
}

fn parse_binding_response(buf: &[u8], expect_tx: [u8; 12]) -> Result<SocketAddr, StunError> {
    if buf.len() < 20 {
        return Err(StunError::ShortResponse);
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagic);
    }
    if buf[8..20] != expect_tx {
        return Err(StunError::TxidMismatch);
    }
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::UnexpectedType(msg_type));
    }
    if 20 + msg_len > buf.len() {
        return Err(StunError::TruncatedAttribute);
    }
    let mut body = &buf[20..20 + msg_len];
    while body.len() >= 4 {
        let atype = u16::from_be_bytes([body[0], body[1]]);
        let alen = u16::from_be_bytes([body[2], body[3]]) as usize;
        if 4 + alen > body.len() {
            return Err(StunError::TruncatedAttribute);
        }
        let val = &body[4..4 + alen];
        let pad = (4 - (alen % 4)) % 4;
        let next = (4 + alen + pad).min(body.len());

        match atype {
            ATTR_XOR_MAPPED => {
                if let Ok(sa) = parse_xor_mapped(val, expect_tx) {
                    return Ok(sa);
                }
            }
            ATTR_MAPPED_ADDR => {
                if let Ok(sa) = parse_mapped(val) {
                    return Ok(sa);
                }
            }
            _ => {}
        }
        body = &body[next..];
    }
    Err(StunError::NoMappedAddress)
}

fn parse_xor_mapped(val: &[u8], tx_id: [u8; 12]) -> Result<SocketAddr, StunError> {
    if val.len() < 8 {
        return Err(StunError::ShortResponse);
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        0x01 => {
            // IPv4: addr XOR with magic cookie
            let xaddr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let addr = xaddr ^ MAGIC_COOKIE;
            Ok(SocketAddr::from((Ipv4Addr::from(addr.to_be_bytes()), port)))
        }
        0x02 => {
            if val.len() < 20 {
                return Err(StunError::ShortResponse);
            }
            // IPv6: addr XOR with (magic cookie || tx_id)
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&tx_id);
            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = val[4 + i] ^ key[i];
            }
            Ok(SocketAddr::from((Ipv6Addr::from(ip), port)))
        }
        f => Err(StunError::UnknownFamily(f)),
    }
}

fn parse_mapped(val: &[u8]) -> Result<SocketAddr, StunError> {
    if val.len() < 8 {
        return Err(StunError::ShortResponse);
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 => Ok(SocketAddr::from((
            Ipv4Addr::new(val[4], val[5], val[6], val[7]),
            port,
        ))),
        0x02 => {
            if val.len() < 20 {
                return Err(StunError::ShortResponse);
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&val[4..20]);
            Ok(SocketAddr::from((Ipv6Addr::from(ip), port)))
        }
        f => Err(StunError::UnknownFamily(f)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic binding-success response with a known XOR-MAPPED
    /// address and verify our parser de-XORs correctly.
    #[test]
    fn parse_xor_mapped_v4() {
        // Public addr: 203.0.113.7:51820
        let public = Ipv4Addr::new(203, 0, 113, 7);
        let port: u16 = 51820;

        let xport = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let xaddr = u32::from(public) ^ MAGIC_COOKIE;

        let mut tx_id = [0u8; 12];
        for (i, b) in tx_id.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut packet = vec![];
        // STUN header
        packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&12u16.to_be_bytes()); // body len
        packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&tx_id);
        // Attribute: XOR-MAPPED-ADDRESS (8-byte value: 0x00, family, xport, xaddr)
        packet.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.push(0x00);
        packet.push(0x01); // family v4
        packet.extend_from_slice(&xport.to_be_bytes());
        packet.extend_from_slice(&xaddr.to_be_bytes());

        let sa = parse_binding_response(&packet, tx_id).unwrap();
        assert_eq!(sa, SocketAddr::new(public.into(), port));
    }
}
