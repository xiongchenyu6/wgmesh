//! End-to-end check: an SSH key derived through our code produces a
//! WireGuard private key whose `wg pubkey` matches our derived public key.
//!
//! This pins protocol-level correctness without needing the Go binary as a
//! reference: WireGuard itself is the oracle.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::io::Write;
use std::process::{Command, Stdio};

fn have(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn ssh_to_wg_matches_wg_pubkey() {
    if !have("ssh-keygen") || !have("wg") {
        eprintln!("skipping: ssh-keygen or wg not installed");
        return;
    }
    let dir = tempdir();
    let key_path = format!("{dir}/host_ed25519");
    let status = Command::new("ssh-keygen")
        .args([
            "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", &key_path,
        ])
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");

    let id =
        wgmesh_core::keyderive::identity_from_ssh_file(&key_path).expect("derive");

    // Pipe our derived priv through `wg pubkey`. Output must equal our pub.
    let priv_b64 = B64.encode(id.wg_priv);
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wg pubkey");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{priv_b64}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait wg pubkey");
    assert!(out.status.success());
    let wg_pub_b64 = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let our_pub_b64 = B64.encode(id.wg_pub);
    assert_eq!(wg_pub_b64, our_pub_b64, "WG-derived pub must match our derivation");

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}

fn tempdir() -> String {
    let base = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = base.join(format!("wgmesh-keyderive-{nanos}"));
    std::fs::create_dir_all(&path).unwrap();
    path.to_string_lossy().into_owned()
}
