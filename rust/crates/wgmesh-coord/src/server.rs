//! HTTP API: POST /register, GET /peers, GET /healthz.
//!
//! All non-/healthz endpoints are signed; verification happens inline in each
//! handler so we can read the body bytes once for both signature check and
//! JSON deserialization.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::sync::Arc;
use tracing::warn;
use wgmesh_core::{api, keyderive, sig};

use crate::config::Config;
use crate::relay::Relay;
use crate::signers::Signers;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub signers: Signers,
    pub relay: Option<Arc<Relay>>,
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/register", post(handle_register))
        .route("/peers", get(handle_peers))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

async fn handle_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let v = match sig::verify(
        header_str(&headers, sig::HEADER_TIMESTAMP),
        header_str(&headers, sig::HEADER_PUBKEY),
        header_str(&headers, sig::HEADER_SIGNATURE),
        "POST",
        "/register",
        &body,
        now_unix(),
        |k| state.signers.contains(k),
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    };
    let req: api::RegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("json: {e}")).into_response(),
    };
    // Bind the data-plane key to the authenticated SSH identity. This also
    // prevents registering a second node's WG key under a different identity.
    let expected = keyderive::wg_pub_from_authorized_line(&v.ssh_pub_line);
    if expected.map(|k| B64.encode(k)).ok().as_deref() != Some(&req.wg_public_key)
        || sig::ed_pub_b64_from_authorized_line(&req.ssh_public_key)
            .ok()
            .as_deref()
            != Some(&v.ed_pub_raw_b64)
        || wgmesh_wglink::validate_public_key(&req.wg_public_key).is_err()
        || req.listen_port == 0
        || req.endpoints.len() > 32
        || req
            .endpoints
            .iter()
            .any(|ep| wgmesh_wglink::validate_endpoint(ep).is_err())
    {
        return (
            StatusCode::BAD_REQUEST,
            "invalid registration or identity/key mismatch",
        )
            .into_response();
    }
    if let Err(e) = state.store.upsert(&v.ed_pub_raw_b64, &req) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Some(r) = state.relay.clone() {
        let res = tokio::task::spawn_blocking(move || r.reconcile()).await;
        if let Ok(Err(e)) = res {
            warn!("relay reconcile after register: {e}");
        }
    }
    let mesh_ip = state
        .store
        .mesh_ip_cidr(&v.ed_pub_raw_b64)
        .unwrap_or_default();
    Json(api::RegisterResponse { mesh_ip }).into_response()
}

async fn handle_peers(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let v = match sig::verify(
        header_str(&headers, sig::HEADER_TIMESTAMP),
        header_str(&headers, sig::HEADER_PUBKEY),
        header_str(&headers, sig::HEADER_SIGNATURE),
        "GET",
        "/peers",
        &body,
        now_unix(),
        |k| state.signers.contains(k),
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    };
    let mut peers =
        state
            .store
            .authorized_peers(&v.ed_pub_raw_b64, state.cfg.peer_ttl, &state.signers);
    if let Some(relay) = state.relay.clone() {
        match tokio::task::spawn_blocking(move || relay.observed_endpoints()).await {
            Ok(Ok(observed)) => crate::relay::add_observed_endpoints(&mut peers, &observed),
            _ => warn!("could not read relay endpoints; returning registered candidates"),
        }
    }
    let resp = api::PeersResponse {
        self_pubkey: v.ed_pub_raw_b64,
        relay: state.relay.as_ref().map(|r| r.info()),
        peers,
    };
    Json(resp).into_response()
}
