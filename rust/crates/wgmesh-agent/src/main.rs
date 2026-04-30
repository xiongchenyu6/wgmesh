use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cfg = wgmesh_agent::AgentConfig::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    wgmesh_agent::run(cfg)
}
