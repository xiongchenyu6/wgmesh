//! ssh-to-wg — same CLI shape as ssh-to-age.
//!
//! With a key file: derive both WireGuard private and public keys from an
//! OpenSSH ed25519 *private* key.
//!
//! With no key file: read SSH *public* keys from stdin (the format produced
//! by `ssh-keyscan` or `~/.ssh/authorized_keys`) and emit the corresponding
//! WireGuard public keys, one per line. Non-ed25519 keys are skipped with a
//! diagnostic on stderr — same behavior as ssh-to-age.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use std::io::BufRead;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-to-wg",
    about = "Derive WireGuard X25519 keys from OpenSSH ed25519 keys.",
    long_about = "With a key file (positional or -i), prints the WG private and \
public keys derived from an OpenSSH ed25519 *private* key.\n\nWith no \
arguments, reads SSH *public* keys from stdin (ssh-keyscan / \
authorized_keys format) and prints WG public keys, one per line. \
Non-ed25519 keys are skipped with a stderr diagnostic."
)]
struct Args {
    /// Path to an OpenSSH ed25519 private key (no passphrase).
    key_path: Option<String>,

    /// Alias for the positional argument; matches `ssh-to-age -i <file>`.
    #[arg(short = 'i', long = "identity")]
    identity: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(p) = args.key_path.or(args.identity) {
        let id = wgmesh_core::keyderive::identity_from_ssh_file(&p)?;
        println!("private: {}", B64.encode(id.wg_priv));
        println!("public:  {}", B64.encode(id.wg_pub));
        return Ok(());
    }

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key_type, pubkey_line)) = pick_pubkey_part(trimmed) else {
            continue;
        };
        if key_type != "ssh-ed25519" {
            eprintln!(
                "skipped key: got {} key type, but only ed25519 keys are supported",
                key_type
            );
            continue;
        }
        match wgmesh_core::keyderive::wg_pub_from_authorized_line(&pubkey_line) {
            Ok(wg_pub) => println!("{}", B64.encode(wg_pub)),
            Err(e) => eprintln!("skipped key: {e}"),
        }
    }
    Ok(())
}

/// Strip the optional ssh-keyscan host/marker prefix and return
/// (key_type, "<key_type> <base64> [comment]").
///
/// `ssh-keyscan` emits `host ssh-ed25519 AAAA…`; `authorized_keys` emits
/// `[options] ssh-ed25519 AAAA… comment`. We find the first whitespace token
/// that looks like an SSH key-type identifier and use that as the start.
fn pick_pubkey_part(line: &str) -> Option<(String, String)> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        if tok.starts_with("ssh-") || tok.starts_with("ecdsa-") || tok.starts_with("sk-") {
            return Some((tok.to_string(), toks[i..].join(" ")));
        }
    }
    None
}
