//! End-to-end coord tests, mirroring `internal/coord/coord_test.go`.
//!
//! Coord runs in `relay_enabled = false` mode here so we don't need kernel
//! WireGuard or root.

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use rand::RngCore;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use wgmesh_core::{api, sig};
use wgmesh_coord::{
    server::{build_app, AppState},
    signers::Signers,
    store::Store,
};

struct TestNode {
    sk: SigningKey,
    line: String,
}

impl TestNode {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let kd = KeyData::Ed25519(Ed25519PublicKey(*vk.as_bytes()));
        let pk = ssh_key::PublicKey::new(kd, "test");
        let line = pk.to_openssh().unwrap();
        Self { sk, line }
    }

    fn signed_request(&self, method: &str, path: &str, body: &[u8]) -> Request<Body> {
        let ts = chrono::Utc::now().timestamp();
        let canon = sig::canonical(ts, method, path, body);
        let signature = self.sk.sign(&canon);
        Request::builder()
            .method(method)
            .uri(path)
            .header("Content-Type", "application/json")
            .header(sig::HEADER_TIMESTAMP, ts.to_string())
            .header(sig::HEADER_PUBKEY, &self.line)
            .header(sig::HEADER_SIGNATURE, B64.encode(signature.to_bytes()))
            .body(Body::from(body.to_vec()))
            .unwrap()
    }
}

fn make_cfg(state: &Path, signers_path: &Path) -> Arc<wgmesh_coord::config::Config> {
    Arc::new(wgmesh_coord::config::Config {
        listen_addr: ":0".into(),
        tls_cert: None,
        tls_key: None,
        mesh_cidr: "10.42.0.0/16".into(),
        state_path: state.to_string_lossy().into_owned(),
        authorized_signers: signers_path.to_string_lossy().into_owned(),
        peer_ttl: Duration::from_secs(600),
        relay_enabled: false,
        relay_ssh_key: String::new(),
        relay_interface: String::new(),
        relay_listen_port: 0,
        relay_endpoint: String::new(),
        relay_mesh_ip: String::new(),
        network_addr: Ipv4Addr::new(10, 42, 0, 0),
        prefix_bits: 16,
    })
}

fn setup(signers: &[&TestNode]) -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let signers_path = dir.path().join("authorized_signers");
    let mut content = String::new();
    for n in signers {
        content.push_str(&n.line);
        content.push('\n');
    }
    std::fs::write(&signers_path, &content).unwrap();
    let state_path = dir.path().join("state.json");
    let cfg = make_cfg(&state_path, &signers_path);
    let store = Arc::new(
        Store::open(
            cfg.state_path.as_str(),
            cfg.network_addr,
            cfg.prefix_bits,
            &[],
        )
        .unwrap(),
    );
    let signers = Signers::load(cfg.authorized_signers.as_str()).unwrap();
    let state = AppState {
        cfg,
        store,
        signers,
        relay: None,
    };
    let app = build_app(state);
    (app, dir)
}

async fn body_to_bytes(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn register_assigns_stable_mesh_ip_and_peers_excludes_self() {
    let a = TestNode::new();
    let b = TestNode::new();
    let (app, _dir) = setup(&[&a, &b]);

    // A registers.
    let reg_a = api::RegisterRequest {
        hostname: "node-a".into(),
        ssh_public_key: a.line.clone(),
        wg_public_key: "AAAA-fake-wg-pub-A".into(),
        endpoints: vec!["1.2.3.4:51820".into()],
        listen_port: 51820,
    };
    let body_a = serde_json::to_vec(&reg_a).unwrap();
    let resp = app
        .clone()
        .oneshot(a.signed_request("POST", "/register", &body_a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let resp_a: api::RegisterResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(
        resp_a.mesh_ip.starts_with("10.42.0.") && resp_a.mesh_ip.ends_with("/16"),
        "unexpected mesh ip: {}",
        resp_a.mesh_ip
    );

    // Re-register A: same mesh IP.
    let resp = app
        .clone()
        .oneshot(a.signed_request("POST", "/register", &body_a))
        .await
        .unwrap();
    let bytes = body_to_bytes(resp.into_body()).await;
    let resp_a2: api::RegisterResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(resp_a.mesh_ip, resp_a2.mesh_ip);

    // B registers.
    let reg_b = api::RegisterRequest {
        hostname: "node-b".into(),
        ssh_public_key: b.line.clone(),
        wg_public_key: "AAAA-fake-wg-pub-B".into(),
        endpoints: vec!["5.6.7.8:51820".into()],
        listen_port: 51820,
    };
    let body_b = serde_json::to_vec(&reg_b).unwrap();
    let resp = app
        .clone()
        .oneshot(b.signed_request("POST", "/register", &body_b))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A fetches /peers — should see B but not itself.
    let resp = app
        .clone()
        .oneshot(a.signed_request("GET", "/peers", b""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let pr: api::PeersResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(pr.peers.len(), 1, "expected 1 peer");
    assert_eq!(pr.peers[0].wg_public_key, "AAAA-fake-wg-pub-B");
    assert_eq!(pr.peers[0].hostname, "node-b");
    assert!(pr.relay.is_none(), "relay should be omitted in coord-only mode");
}

#[tokio::test]
async fn register_rejects_unknown_signer() {
    let a = TestNode::new();
    let intruder = TestNode::new(); // not in allowlist
    let (app, _dir) = setup(&[&a]);

    let body = serde_json::to_vec(&api::RegisterRequest {
        hostname: "x".into(),
        ssh_public_key: intruder.line.clone(),
        wg_public_key: "X".into(),
        endpoints: vec![],
        listen_port: 0,
    })
    .unwrap();
    let resp = app
        .oneshot(intruder.signed_request("POST", "/register", &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_rejects_missing_signature_headers() {
    let a = TestNode::new();
    let (app, _dir) = setup(&[&a]);

    let body = serde_json::to_vec(&api::RegisterRequest {
        hostname: "x".into(),
        ssh_public_key: String::new(),
        wg_public_key: "X".into(),
        endpoints: vec![],
        listen_port: 0,
    })
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn store_persists_assignment_across_reopen() {
    let a = TestNode::new();
    let (app, dir) = setup(&[&a]);

    let body = serde_json::to_vec(&api::RegisterRequest {
        hostname: "x".into(),
        ssh_public_key: a.line.clone(),
        wg_public_key: "K".into(),
        endpoints: vec!["1.1.1.1:51820".into()],
        listen_port: 51820,
    })
    .unwrap();
    let resp = app
        .oneshot(a.signed_request("POST", "/register", &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-open the store directly; A's assignment must still be there.
    let state_path = dir.path().join("state.json");
    let store2 = Store::open(
        state_path.to_str().unwrap(),
        Ipv4Addr::new(10, 42, 0, 0),
        16,
        &[],
    )
    .unwrap();
    let raw = sig::ed_pub_b64_from_authorized_line(&a.line).unwrap();
    assert!(
        store2.mesh_ip_cidr(&raw).is_some(),
        "expected persisted assignment"
    );
}

#[tokio::test]
async fn healthz_unauthenticated() {
    let a = TestNode::new();
    let (app, _dir) = setup(&[&a]);
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    assert_eq!(&bytes[..], b"ok");
}
