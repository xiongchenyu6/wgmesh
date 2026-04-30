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

/// Bring up coord: load config, open store, start relay (if enabled), serve HTTP.
/// Reload signers on SIGHUP, periodic relay reconcile every 30s.
pub async fn run(config_path: &str) -> Result<()> {
    let cfg = Arc::new(config::load(config_path)?);
    info!(addr = %cfg.listen_addr, mesh = %cfg.mesh_cidr, relay = cfg.relay_enabled, "coord starting");

    let reserved: Vec<&str> = if cfg.relay_enabled {
        vec![cfg.relay_mesh_ip.as_str()]
    } else {
        vec![]
    };
    let store = Arc::new(store::Store::open(
        &cfg.state_path,
        cfg.network_addr,
        cfg.prefix_bits,
        &reserved,
    )?);

    let signers = signers::Signers::load(&cfg.authorized_signers)
        .context("load authorized_signers")?;

    let relay = if cfg.relay_enabled {
        Some(Arc::new(relay::Relay::start(cfg.clone(), store.clone())?))
    } else {
        None
    };

    let state = server::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        signers: signers.clone(),
        relay: relay.clone(),
    };

    // SIGHUP → reload allowlist.
    {
        let signers = signers.clone();
        let mut hup = signal(SignalKind::hangup())?;
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                match signers.reload() {
                    Ok(()) => info!("authorized_signers reloaded"),
                    Err(e) => warn!("reload failed: {e}"),
                }
            }
        });
    }

    // Periodic relay reconcile (30s).
    if let Some(r) = relay.clone() {
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
                    warn!("periodic relay reconcile: {e}");
                }
            }
        });
    }

    let app = server::build_app(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr_normalized()).await?;
    info!(local = ?listener.local_addr().ok(), "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok(); };
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    info!("shutdown requested");
}
