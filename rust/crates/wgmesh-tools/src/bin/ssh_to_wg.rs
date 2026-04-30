//! Read an OpenSSH ed25519 private key and print the matching WG keypair.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-to-wg",
    about = "Derive a WireGuard X25519 keypair from an OpenSSH ed25519 host key"
)]
struct Args {
    /// Path to the OpenSSH ed25519 private key (no passphrase).
    key_path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let id = wgmesh_core::keyderive::identity_from_ssh_file(&args.key_path)?;
    println!("private: {}", B64.encode(id.wg_priv));
    println!("public:  {}", B64.encode(id.wg_pub));
    Ok(())
}
