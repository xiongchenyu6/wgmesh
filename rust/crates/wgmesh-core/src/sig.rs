//! Request signing scheme between agent and coord.
//!
//! Canonical bytes:
//! ```text
//!   TIMESTAMP "\n" METHOD "\n" PATH "\n" SHA256_HEX(BODY)
//! ```
//! signed with the agent's SSH ed25519 host key. The coordinator authorizes
//! the request by looking up the *raw 32-byte ed25519 public key* (base64) in
//! its `authorized_signers` allowlist.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ssh_key::PublicKey;
use thiserror::Error;

pub const HEADER_TIMESTAMP: &str = "X-Sig-Timestamp";
pub const HEADER_PUBKEY: &str = "X-Sig-Pubkey";
pub const HEADER_SIGNATURE: &str = "X-Sig-Signature";
/// ±60s skew window matched on both sides.
pub const MAX_SKEW_SECS: i64 = 60;

#[derive(Debug, Error)]
pub enum SigError {
    #[error("missing signature header")]
    MissingHeader,
    #[error("bad timestamp: {0}")]
    BadTimestamp(String),
    #[error("timestamp skew {0}s exceeds {1}s")]
    Skew(i64, i64),
    #[error("parse pubkey: {0}")]
    ParsePubkey(String),
    #[error("unsupported key type {0}")]
    UnsupportedKeyType(String),
    #[error("pubkey not authorized")]
    NotAuthorized,
    #[error("bad signature encoding")]
    BadSignatureEncoding,
    #[error("signature verification failed")]
    BadSig,
}

/// Build the canonical bytes that get signed/verified.
pub fn canonical(timestamp: i64, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let body_hex = hex::encode(Sha256::digest(body));
    format!("{timestamp}\n{method}\n{path}\n{body_hex}").into_bytes()
}

/// Sign and return the base64-encoded signature ready for `X-Sig-Signature`.
pub fn sign(timestamp: i64, method: &str, path: &str, body: &[u8], sk: &SigningKey) -> String {
    let canon = canonical(timestamp, method, path, body);
    let sig = sk.sign(&canon);
    B64.encode(sig.to_bytes())
}

#[derive(Debug, Clone)]
pub struct Verified {
    /// The original `X-Sig-Pubkey` line.
    pub ssh_pub_line: String,
    /// base64 of the raw 32-byte ed25519 public key — the stable identity.
    pub ed_pub_raw_b64: String,
}

/// Extract the raw ed25519 public key (base64) from a single
/// `ssh-ed25519 AAAA... comment` line, as in `authorized_keys`.
pub fn ed_pub_b64_from_authorized_line(line: &str) -> Result<String, SigError> {
    let pk = PublicKey::from_openssh(line.trim())
        .map_err(|e| SigError::ParsePubkey(e.to_string()))?;
    let ed = pk
        .key_data()
        .ed25519()
        .ok_or_else(|| SigError::UnsupportedKeyType(pk.algorithm().to_string()))?;
    Ok(B64.encode(ed.0))
}

/// Verify the signature headers against (timestamp, method, path, body).
///
/// `now` is the server's current Unix timestamp; passed in for testability.
/// `authorized` returns true iff the parsed `EdPubRawB64` is allowed.
pub fn verify(
    ts_str: &str,
    pub_str: &str,
    sig_str: &str,
    method: &str,
    path: &str,
    body: &[u8],
    now: i64,
    authorized: impl Fn(&str) -> bool,
) -> Result<Verified, SigError> {
    if ts_str.is_empty() || pub_str.is_empty() || sig_str.is_empty() {
        return Err(SigError::MissingHeader);
    }
    let ts: i64 = ts_str
        .parse()
        .map_err(|_| SigError::BadTimestamp(ts_str.to_string()))?;
    let d = now - ts;
    if d > MAX_SKEW_SECS || d < -MAX_SKEW_SECS {
        return Err(SigError::Skew(d, MAX_SKEW_SECS));
    }
    let pk = PublicKey::from_openssh(pub_str.trim())
        .map_err(|e| SigError::ParsePubkey(e.to_string()))?;
    let ed = pk
        .key_data()
        .ed25519()
        .ok_or_else(|| SigError::UnsupportedKeyType(pk.algorithm().to_string()))?;
    let raw_b64 = B64.encode(ed.0);
    if !authorized(&raw_b64) {
        return Err(SigError::NotAuthorized);
    }
    let sig_bytes = B64
        .decode(sig_str)
        .map_err(|_| SigError::BadSignatureEncoding)?;
    if sig_bytes.len() != 64 {
        return Err(SigError::BadSig);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    let vk = VerifyingKey::from_bytes(&ed.0).map_err(|_| SigError::BadSig)?;
    let canon = canonical(ts, method, path, body);
    vk.verify(&canon, &sig).map_err(|_| SigError::BadSig)?;
    Ok(Verified {
        ssh_pub_line: pub_str.to_string(),
        ed_pub_raw_b64: raw_b64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let raw_b64 = B64.encode(vk.as_bytes());
        // Fake an SSH wire-format pubkey by reusing the raw bytes.
        // ssh-key's PublicKey::from(...) accepts an Ed25519PublicKey.
        let ed_pub = ssh_key::public::Ed25519PublicKey(*vk.as_bytes());
        let pk = ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Ed25519(ed_pub),
            "test@unit",
        );
        let pub_line = pk.to_openssh().unwrap();
        let _ = raw_b64;
        (sk, pub_line)
    }

    #[test]
    fn canonical_is_stable() {
        let a = canonical(1700000000, "POST", "/register", b"{}");
        let b = canonical(1700000000, "POST", "/register", b"{}");
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_differs_on_body() {
        let a = canonical(1, "POST", "/r", b"a");
        let b = canonical(1, "POST", "/r", b"b");
        assert_ne!(a, b);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pub_line) = fixture();
        let now: i64 = 1_700_000_000;
        let body = b"{\"hello\":1}";
        let sig_b64 = sign(now, "POST", "/register", body, &sk);

        let v = verify(
            &now.to_string(),
            &pub_line,
            &sig_b64,
            "POST",
            "/register",
            body,
            now,
            |_| true,
        )
        .expect("verify ok");
        assert!(!v.ed_pub_raw_b64.is_empty());
    }

    #[test]
    fn skew_rejected() {
        let (sk, pub_line) = fixture();
        let signed_at: i64 = 1_700_000_000;
        let server_now = signed_at + MAX_SKEW_SECS + 1;
        let sig_b64 = sign(signed_at, "GET", "/peers", b"", &sk);
        let r = verify(
            &signed_at.to_string(),
            &pub_line,
            &sig_b64,
            "GET",
            "/peers",
            b"",
            server_now,
            |_| true,
        );
        assert!(matches!(r, Err(SigError::Skew(_, _))));
    }

    #[test]
    fn unauthorized_rejected() {
        let (sk, pub_line) = fixture();
        let now: i64 = 1_700_000_000;
        let sig_b64 = sign(now, "GET", "/peers", b"", &sk);
        let r = verify(
            &now.to_string(),
            &pub_line,
            &sig_b64,
            "GET",
            "/peers",
            b"",
            now,
            |_| false,
        );
        assert!(matches!(r, Err(SigError::NotAuthorized)));
    }

    #[test]
    fn tamper_body_rejected() {
        let (sk, pub_line) = fixture();
        let now: i64 = 1_700_000_000;
        let sig_b64 = sign(now, "POST", "/register", b"original", &sk);
        let r = verify(
            &now.to_string(),
            &pub_line,
            &sig_b64,
            "POST",
            "/register",
            b"tampered",
            now,
            |_| true,
        );
        assert!(matches!(r, Err(SigError::BadSig)));
    }

    #[test]
    fn ed_pub_b64_extraction() {
        let (_, pub_line) = fixture();
        let raw = ed_pub_b64_from_authorized_line(&pub_line).unwrap();
        // Round-trip: base64 → 32 bytes.
        let bytes = B64.decode(raw).unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
