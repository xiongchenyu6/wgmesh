//! ssh-to-wg — same CLI as `ssh-to-age`.
//!
//! ```text
//! Usage of ssh-to-wg:
//!   -i string
//!         Input path. Reads by default from standard input (default "-")
//!   -o string
//!         Output path. Prints by default to standard output (default "-")
//!   -private-key
//!         convert private key instead of public key
//! ```
//!
//! Default mode (public key): each input line is parsed as
//! `ssh-keyscan` / `authorized_keys` output. Non-ed25519 keys are skipped
//! with a stderr diagnostic. WG public keys are written, one per line.
//!
//! With `-private-key`: input must be an OpenSSH ed25519 PRIVATE key file
//! (no passphrase). Output is two lines:
//! ```text
//! # public key: <wg-pub-base64>
//! <wg-priv-base64>
//! ```

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

const HELP: &str = "\
Usage of ssh-to-wg:
  -i string
        Input path. Reads by default from standard input (default \"-\")
  -o string
        Output path. Prints by default to standard output (default \"-\")
  -private-key
        convert private key instead of public key
";

#[derive(Debug)]
struct CliArgs {
    input: String,
    output: String,
    private_key: bool,
}

fn parse_cli<I: Iterator<Item = String>>(mut args: I) -> Result<CliArgs> {
    let _prog = args.next();
    let mut a = CliArgs {
        input: "-".to_string(),
        output: "-".to_string(),
        private_key: false,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "-help" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-i" | "--input" => {
                a.input = args
                    .next()
                    .ok_or_else(|| anyhow!("flag needs an argument: -i"))?;
            }
            // ssh-to-age also accepts -i=foo style; handle both
            s if s.starts_with("-i=") => a.input = s[3..].to_string(),
            s if s.starts_with("--input=") => a.input = s[8..].to_string(),
            "-o" | "--output" => {
                a.output = args
                    .next()
                    .ok_or_else(|| anyhow!("flag needs an argument: -o"))?;
            }
            s if s.starts_with("-o=") => a.output = s[3..].to_string(),
            s if s.starts_with("--output=") => a.output = s[9..].to_string(),
            "-private-key" | "--private-key" => a.private_key = true,
            other => bail!("unknown argument: {other}\n\n{HELP}"),
        }
    }
    Ok(a)
}

fn main() -> Result<()> {
    let args = parse_cli(std::env::args())?;
    let mut out = open_writer(&args.output)?;
    if args.private_key {
        run_private(&args.input, out.as_mut())?;
    } else {
        run_public(&args.input, out.as_mut())?;
    }
    out.flush()?;
    Ok(())
}

fn run_public(input_path: &str, out: &mut dyn Write) -> Result<()> {
    let reader = open_reader(input_path)?;
    for line in reader.lines() {
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
            Ok(wg_pub) => writeln!(out, "{}", B64.encode(wg_pub))?,
            Err(e) => eprintln!("skipped key: {e}"),
        }
    }
    Ok(())
}

fn run_private(input_path: &str, out: &mut dyn Write) -> Result<()> {
    let pem = read_all(input_path)?;
    let id = wgmesh_core::keyderive::identity_from_pem(&pem)
        .with_context(|| format!("parse private key from {input_path}"))?;
    writeln!(out, "# public key: {}", B64.encode(id.wg_pub))?;
    writeln!(out, "{}", B64.encode(id.wg_priv))?;
    Ok(())
}

/// Strip optional ssh-keyscan host/marker prefix and return
/// `(key_type, "<key_type> <base64> [comment]")`.
fn pick_pubkey_part(line: &str) -> Option<(String, String)> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        if tok.starts_with("ssh-") || tok.starts_with("ecdsa-") || tok.starts_with("sk-") {
            return Some((tok.to_string(), toks[i..].join(" ")));
        }
    }
    None
}

fn open_reader(path: &str) -> Result<Box<dyn BufRead>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(io::stdin())))
    } else {
        let f = std::fs::File::open(Path::new(path))
            .with_context(|| format!("open {path}"))?;
        Ok(Box::new(BufReader::new(f)))
    }
}

fn open_writer(path: &str) -> Result<Box<dyn Write>> {
    if path == "-" {
        Ok(Box::new(io::stdout()))
    } else {
        let f = std::fs::File::create(Path::new(path))
            .with_context(|| format!("create {path}"))?;
        Ok(Box::new(f))
    }
}

fn read_all(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path).with_context(|| format!("read {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        std::iter::once("ssh-to-wg")
            .chain(v.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn defaults() {
        let a = parse_cli(args(&[]).into_iter()).unwrap();
        assert_eq!(a.input, "-");
        assert_eq!(a.output, "-");
        assert!(!a.private_key);
    }

    #[test]
    fn dash_i_separate() {
        let a = parse_cli(args(&["-i", "/tmp/k"]).into_iter()).unwrap();
        assert_eq!(a.input, "/tmp/k");
    }

    #[test]
    fn dash_i_equals() {
        let a = parse_cli(args(&["-i=/tmp/k"]).into_iter()).unwrap();
        assert_eq!(a.input, "/tmp/k");
    }

    #[test]
    fn private_key_single_dash() {
        let a = parse_cli(args(&["-private-key"]).into_iter()).unwrap();
        assert!(a.private_key);
    }

    #[test]
    fn private_key_double_dash_also_works() {
        let a = parse_cli(args(&["--private-key"]).into_iter()).unwrap();
        assert!(a.private_key);
    }

    #[test]
    fn unknown_arg_errors() {
        let r = parse_cli(args(&["--bogus"]).into_iter());
        assert!(r.is_err());
    }
}
