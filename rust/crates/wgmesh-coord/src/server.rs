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
use std::sync::Arc;
use tracing::warn;
use wgmesh_core::{api, sig};

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
    if req.wg_public_key.is_empty() {
        return (StatusCode::BAD_REQUEST, "wg_public_key required").into_response();
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

async fn handle_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
    let peers = state.store.peers(&v.ed_pub_raw_b64, state.cfg.peer_ttl);
    let resp = api::PeersResponse {
        self_pubkey: v.ed_pub_raw_b64,
        relay: state.relay.as_ref().map(|r| r.info()),
        peers,
    };
    Json(resp).into_response()
}
