//! Fake-node CLI: register against a running coord and dump /peers.
//! Use for local end-to-end checks without bringing up a real wg0.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use std::io::Read;
use wgmesh_core::{api, keyderive, sig};

#[derive(Parser, Debug)]
#[command(name = "wgmesh-smoketest", about = "smoke-test a wgmesh coordinator")]
struct Args {
    /// Path to OpenSSH ed25519 private key whose pubkey is in the coord's
    /// authorized_signers file.
    #[arg(long)]
    key: String,
    /// Coord base URL, e.g. http://127.0.0.1:8443
    #[arg(long)]
    base: String,
    /// Hostname to advertise.
    #[arg(long, default_value = "smoketest")]
    hostname: String,
    /// Endpoints to advertise (comma-separated).
    #[arg(long, value_delimiter = ',')]
    endpoints: Vec<String>,
    /// WG listen port to advertise.
    #[arg(long, default_value_t = 51820)]
    port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let id = keyderive::identity_from_ssh_file(&args.key)?;
    let pub_line = id.ssh_pub_line.clone();
    let sk = id.ed_signing;
    let wg_pub_b64 = B64.encode(id.wg_pub);
    let base = args.base.trim_end_matches('/').to_string();

    let req = api::RegisterRequest {
        hostname: args.hostname,
        ssh_public_key: pub_line.clone(),
        wg_public_key: wg_pub_b64,
        endpoints: args.endpoints,
        listen_port: args.port,
    };
    let body = serde_json::to_vec(&req)?;
    let resp_bytes = signed_post(&base, "/register", &body, &sk, &pub_line)?;
    let resp: api::RegisterResponse = serde_json::from_slice(&resp_bytes)?;
    println!("registered, mesh_ip = {}", resp.mesh_ip);

    let peers_bytes = signed_get(&base, "/peers", &sk, &pub_line)?;
    let pr: api::PeersResponse = serde_json::from_slice(&peers_bytes)?;
    println!("relay: {:?}", pr.relay);
    println!("peers ({}):", pr.peers.len());
    for p in &pr.peers {
        println!(
            "  - {} {} endpoints={:?} last_seen={}",
            p.hostname, p.mesh_ip, p.endpoints, p.last_seen
        );
    }
    Ok(())
}

fn signed_post(
    base: &str,
    path: &str,
    body: &[u8],
    sk: &ed25519_dalek::SigningKey,
    pub_line: &str,
) -> Result<Vec<u8>> {
    let ts = chrono::Utc::now().timestamp();
    let sig_b64 = sig::sign(ts, "POST", path, body, sk);
    let url = format!("{base}{path}");
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set(sig::HEADER_TIMESTAMP, &ts.to_string())
        .set(sig::HEADER_PUBKEY, pub_line)
        .set(sig::HEADER_SIGNATURE, &sig_b64)
        .send_bytes(body);
    handle(resp, "POST", path)
}

fn signed_get(
    base: &str,
    path: &str,
    sk: &ed25519_dalek::SigningKey,
    pub_line: &str,
) -> Result<Vec<u8>> {
    let ts = chrono::Utc::now().timestamp();
    let sig_b64 = sig::sign(ts, "GET", path, b"", sk);
    let url = format!("{base}{path}");
    let resp = ureq::get(&url)
        .set("Content-Type", "application/json")
        .set(sig::HEADER_TIMESTAMP, &ts.to_string())
        .set(sig::HEADER_PUBKEY, pub_line)
        .set(sig::HEADER_SIGNATURE, &sig_b64)
        .call();
    handle(resp, "GET", path)
}

fn handle(
    r: Result<ureq::Response, ureq::Error>,
    method: &str,
    path: &str,
) -> Result<Vec<u8>> {
    match r {
        Ok(resp) => {
            let mut buf = Vec::new();
            resp.into_reader().take(1_048_576).read_to_end(&mut buf)?;
            Ok(buf)
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            Err(anyhow!("{method} {path}: status {code}: {}", body.trim()))
        }
        Err(e) => Err(anyhow!("{method} {path}: {e}")),
    }
}
