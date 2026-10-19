//! wgmesh coordinator. See `services.wgmesh-coord` for production deployment;
//! `cargo test -p wgmesh-coord` for unit and integration tests.

pub mod config;
pub mod relay;
pub mod server;
pub mod signers;
pub mod store;

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

/// Bring up coord: load config, open store, start the WG hub, serve HTTP.
/// Reload signers on SIGHUP, periodic WG-peer reconcile every 30s.
pub async fn run(config_path: &str) -> Result<()> {
    let cfg = Arc::new(config::load(config_path)?);
    // Load certificates before changing kernel state; invalid TLS fails closed.
    let tls = load_tls(&cfg).await?;
    info!(addr = %cfg.listen_addr, mesh = %cfg.mesh_cidr, "coord starting");

    let store = Arc::new(store::Store::open(
        &cfg.state_path,
        cfg.network_addr,
        cfg.prefix_bits,
        &[cfg.wg_mesh_ip.as_str()],
    )?);
    store.set_static_ips(cfg.static_ips.clone());

    let signers =
        signers::Signers::load(&cfg.authorized_signers).context("load authorized_signers")?;

    // Coord *always* runs the WG hub: every agent is one of its peers.
    let relay = Arc::new(relay::Relay::start(
        cfg.clone(),
        store.clone(),
        signers.clone(),
    )?);

    let state = server::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        signers: signers.clone(),
        relay: Some(relay.clone()),
    };

    // SIGHUP → reload allowlist.
    {
        let signers = signers.clone();
        let relay = relay.clone();
        let tls = tls.clone();
        let cfg = cfg.clone();
        let store = store.clone();
        let config_path = config_path.to_string();
        let mut hup = signal(SignalKind::hangup())?;
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                // Keep the current valid certificate if renewal files are bad;
                // signer revocation must still proceed independently.
                if let Some(tls) = &tls {
                    if let Err(e) = reload_tls(tls, &cfg).await {
                        warn!("TLS reload failed (keeping current certificate): {e}");
                    }
                }
                reload_static_ips(&config_path, &cfg, &store);
                match signers.reload() {
                    Ok(()) => {
                        let relay = relay.clone();
                        match tokio::task::spawn_blocking(move || relay.reconcile()).await {
                            Ok(Ok(())) => {
                                info!("authorized_signers reloaded; relay peers reconciled")
                            }
                            other => warn!(?other, "revocation relay cleanup failed"),
                        }
                    }
                    Err(e) => warn!("reload failed: {e}"),
                }
            }
        });
    }

    // Periodic WG-peer reconcile (30s).
    {
        let r = relay.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await; // skip immediate
            loop {
                interval.tick().await;
                let r = r.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || r.reconcile())
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")))
                {
                    warn!("periodic WG reconcile: {e}");
                }
            }
        });
    }

    let app = server::build_app(state);
    let listener = std::net::TcpListener::bind(cfg.listen_addr_normalized())?;
    listener.set_nonblocking(true)?;
    info!(local = ?listener.local_addr().ok(), tls = tls.is_some(), "listening");
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    serve(listener, app, tls, handle).await
}

/// Re-read `static_ips` from the config file. A config that fails validation,
/// or whose mesh settings changed (those need a restart), is ignored and the
/// current reservations stay in force.
fn reload_static_ips(config_path: &str, running: &config::Config, store: &store::Store) {
    match config::load(config_path) {
        Ok(new) if new.mesh_cidr == running.mesh_cidr && new.wg_mesh_ip == running.wg_mesh_ip => {
            let count = new.static_ips.len();
            store.set_static_ips(new.static_ips);
            info!(count, "static_ips reloaded");
        }
        Ok(_) => {
            warn!("mesh_cidr/wg_mesh_ip changed; restart required (keeping current static_ips)")
        }
        Err(e) => warn!("config reload failed (keeping current static_ips): {e}"),
    }
}

pub async fn load_tls(
    cfg: &config::Config,
) -> Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    match (&cfg.tls_cert, &cfg.tls_key) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            Ok(Some(
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                    .await
                    .context("load TLS certificate and private key")?,
            ))
        }
        _ => anyhow::bail!("tls_cert and tls_key must be configured together"),
    }
}

pub async fn reload_tls(
    tls: &axum_server::tls_rustls::RustlsConfig,
    cfg: &config::Config,
) -> Result<()> {
    let cert = cfg.tls_cert.as_ref().context("missing tls_cert")?;
    let key = cfg.tls_key.as_ref().context("missing tls_key")?;
    tls.reload_from_pem_file(cert, key)
        .await
        .context("reload TLS certificate and key")?;
    Ok(())
}

pub async fn serve(
    listener: std::net::TcpListener,
    app: axum::Router,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    handle: axum_server::Handle,
) -> Result<()> {
    match tls {
        Some(tls) => {
            axum_server::from_tcp_rustls(listener, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await?
        }
        None => {
            axum_server::from_tcp(listener)
                .handle(handle)
                .serve(app.into_make_service())
                .await?
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cfg(dir: &std::path::Path, static_ips: serde_json::Value) -> String {
        let path = dir.join("coord.json");
        let body = serde_json::json!({
            "mesh_cidr": "10.42.0.0/16",
            "state_path": dir.join("state.json"),
            "authorized_signers": dir.join("signers"),
            "static_ips": static_ips,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn key_line(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let kd = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            sk.verifying_key().to_bytes(),
        ));
        ssh_key::PublicKey::new(kd, "t").to_openssh().unwrap()
    }

    #[test]
    fn reload_applies_valid_static_ips_and_keeps_old_on_bad_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(dir.path(), serde_json::json!({}));
        let running = config::load(&path).unwrap();
        let store = store::Store::open(
            running.state_path.as_str(),
            running.network_addr,
            running.prefix_bits,
            &[running.wg_mesh_ip.as_str()],
        )
        .unwrap();
        let req = wgmesh_core::api::RegisterRequest {
            hostname: "h".into(),
            ssh_public_key: String::new(),
            wg_public_key: "w".into(),
            endpoints: vec![],
            listen_port: 51820,
        };
        let key = wgmesh_core::sig::ed_pub_b64_from_authorized_line(&key_line(1)).unwrap();

        write_cfg(dir.path(), serde_json::json!({"10.42.0.9": key_line(1)}));
        reload_static_ips(&path, &running, &store);
        assert_eq!(store.upsert(&key, &req).unwrap(), "10.42.0.9");

        // Out-of-mesh IP: reload must keep 10.42.0.9, not drop or apply it.
        write_cfg(dir.path(), serde_json::json!({"192.0.2.9": key_line(1)}));
        reload_static_ips(&path, &running, &store);
        assert_eq!(store.upsert(&key, &req).unwrap(), "10.42.0.9");
    }
}
