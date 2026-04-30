use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "wgmesh-agent", about = "wgmesh node agent")]
pub struct AgentConfig {
    /// Path to OpenSSH ed25519 host private key. Used both for HTTP signing
    /// and for deriving the WG keypair.
    #[arg(
        long = "ssh-key",
        env = "WGMESH_SSH_KEY",
        default_value = "/etc/ssh/ssh_host_ed25519_key"
    )]
    pub ssh_key: String,

    /// Coordinator base URL, e.g. `https://mesh.example.com:8443`.
    #[arg(long = "coordinator", env = "WGMESH_COORDINATOR")]
    pub coordinator: String,

    /// STUN server, e.g. `stun.example.com:3478`. Set empty/unset to skip.
    #[arg(long = "stun", env = "WGMESH_STUN", default_value = "")]
    pub stun_server: String,

    /// WG kernel interface name.
    #[arg(long = "interface", env = "WGMESH_IFACE", default_value = "wg0")]
    pub interface: String,

    /// WG UDP listen port.
    #[arg(long = "listen-port", env = "WGMESH_LISTEN_PORT", default_value_t = 51820)]
    pub listen_port: u16,

    /// Reconcile interval in seconds.
    #[arg(long = "poll-secs", env = "WGMESH_POLL_SECS", default_value_t = 30)]
    pub poll_secs: u64,

    /// Hostname advertised to coord. Defaults to `gethostname()`.
    #[arg(long = "hostname", env = "WGMESH_HOSTNAME")]
    pub hostname: Option<String>,

    /// Advertise LAN endpoints (every non-loopback IPv4/v6 on every UP iface).
    #[arg(long = "include-lan", env = "WGMESH_INCLUDE_LAN", default_value_t = false)]
    pub include_lan: bool,

    /// Comma-separated interface names to skip when enumerating LAN endpoints.
    #[arg(long = "skip-iface", env = "WGMESH_SKIP_IFACE", value_delimiter = ',')]
    pub skip_iface: Vec<String>,
}
