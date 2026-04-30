//! Synchronous, signed HTTP client for the coordinator.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use std::io::Read;
use wgmesh_core::{api, keyderive, sig};

pub struct CoordClient {
    base_url: String,
    sk: SigningKey,
    pub_line: String,
}

impl CoordClient {
    pub fn new(base_url: &str, ssh_key_path: &str) -> Result<Self> {
        let id = keyderive::identity_from_ssh_file(ssh_key_path)
            .with_context(|| format!("load identity from {ssh_key_path}"))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            sk: id.ed_signing,
            pub_line: id.ssh_pub_line,
        })
    }

    pub fn pub_line(&self) -> &str {
        &self.pub_line
    }

    pub fn register(&self, req: &api::RegisterRequest) -> Result<api::RegisterResponse> {
        let body = serde_json::to_vec(req)?;
        let bytes = self.do_request("POST", "/register", &body)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn peers(&self) -> Result<api::PeersResponse> {
        let bytes = self.do_request("GET", "/peers", b"")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn do_request(&self, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let ts = chrono::Utc::now().timestamp();
        let sig_b64 = sig::sign(ts, method, path, body, &self.sk);
        let url = format!("{}{}", self.base_url, path);

        let mut req = match method {
            "POST" => ureq::post(&url),
            "GET" => ureq::get(&url),
            other => return Err(anyhow!("unsupported method {other}")),
        };
        req = req
            .set("Content-Type", "application/json")
            .set(sig::HEADER_TIMESTAMP, &ts.to_string())
            .set(sig::HEADER_PUBKEY, &self.pub_line)
            .set(sig::HEADER_SIGNATURE, &sig_b64);

        let resp = if method == "POST" {
            req.send_bytes(body)
        } else {
            req.call()
        };

        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(anyhow!("{method} {path}: status {code}: {}", body.trim()));
            }
            Err(e) => return Err(anyhow!("{method} {path}: {e}")),
        };

        let mut buf = Vec::new();
        resp.into_reader()
            .take(1_048_576)
            .read_to_end(&mut buf)?;
        Ok(buf)
    }
}
