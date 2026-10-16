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
