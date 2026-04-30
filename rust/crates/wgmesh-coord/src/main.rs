use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "wgmesh-coord", about = "wgmesh coordinator service")]
struct Args {
    /// Path to JSON config file.
    #[arg(short = 'c', long = "config")]
    config: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    // Single-threaded runtime keeps RSS small; coord workload is I/O light.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(wgmesh_coord::run(&args.config))
}
