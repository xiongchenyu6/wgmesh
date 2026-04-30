{ config, lib, pkgs, ... }:

let
  cfg = config.services.wgmesh-coord;

  # The coordinator always runs the WG hub (it's both an HTTP server *and*
  # a WireGuard peer with every agent). Field naming reflects that — no
  # `relay` jargon, just plain "wg" since WireGuard is the only data path.
  configAttrs = lib.filterAttrs (n: v: v != null && v != "") {
    listen_addr        = cfg.listenAddr;
    tls_cert           = cfg.tlsCert;
    tls_key            = cfg.tlsKey;
    mesh_cidr          = cfg.meshCidr;
    state_path         = "${cfg.stateDir}/state.json";
    authorized_signers = cfg.authorizedSignersPath;
    peer_ttl_seconds   = cfg.peerTTLSeconds;
    wg_ssh_key         = cfg.sshKeyPath;
    wg_interface       = cfg.interface;
    wg_listen_port     = cfg.wgListenPort;
    wg_endpoint_host   = cfg.endpointHost;
    wg_mesh_ip         = cfg.meshIP;
  };
  configFile = pkgs.writeText "wgmesh-coord.json" (builtins.toJSON configAttrs);

  listenPortFromAddr =
    let parts = lib.splitString ":" cfg.listenAddr;
    in lib.toInt (lib.last parts);
in
{
  options.services.wgmesh-coord = {
    enable = lib.mkEnableOption "wgmesh coordinator (HTTP API + WireGuard hub)";

    package = lib.mkOption {
      type = lib.types.package;
      description = "wgmesh package providing the wgmesh-coord binary.";
    };

    ## Required ----------------------------------------------------------------

    meshCidr = lib.mkOption {
      type = lib.types.str;
      example = "10.42.0.0/16";
      description = "IPv4 CIDR for mesh IP allocation.";
    };

    authorizedSignersPath = lib.mkOption {
      type = lib.types.path;
      example = "/etc/wgmesh/authorized_signers";
      description = "OpenSSH ed25519 pubkey allowlist; SIGHUP reloads.";
    };

    ## Common ------------------------------------------------------------------

    listenAddr = lib.mkOption {
      type = lib.types.str;
      default = ":8443";
      description = "HTTP API listen address.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open both the HTTP TCP port and the WG UDP port in the firewall.";
    };

    ## Advanced (sensible defaults) -------------------------------------------

    endpointHost = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "wg.example.com";
      description = ''
        OPTIONAL override for the hostname agents reach the coordinator's
        WireGuard on. Empty (the default) means: agents derive the host
        from their own `services.wgmesh.coordinator` URL — set this only
        when WG must run on a different domain than HTTP (e.g., HTTP is
        behind a TCP-only CDN that can't proxy UDP).
      '';
    };

    wgListenPort = lib.mkOption {
      type = lib.types.port;
      default = 51820;
      description = "UDP port the coordinator's WG interface listens on; published to agents via /peers.";
    };

    sshKeyPath = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = ''
        OpenSSH ed25519 host key used to derive the coordinator's WG keypair.
        Default = the host key your `services.openssh` already manages.
      '';
    };

    interface = lib.mkOption {
      type = lib.types.str;
      default = "wg0";
      description = "Kernel WireGuard interface name on the coordinator.";
    };

    meshIP = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "10.42.0.1";
      description = ''
        Coordinator's mesh IP. Empty means: use the first usable address
        in meshCidr (e.g. `10.42.0.1` for `/16`).
      '';
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/wgmesh-coord";
      description = "Where `state.json` lives (stable mesh-IP assignments).";
    };

    peerTTLSeconds = lib.mkOption {
      type = lib.types.int;
      default = 600;
      description = "Peers absent longer than this are hidden from /peers.";
    };

    tlsCert = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "TLS certificate path. Empty for plain HTTP behind a reverse proxy.";
    };

    tlsKey = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "TLS private key path.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
    ];

    boot.kernelModules = [ "wireguard" ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

    systemd.services.wgmesh-coord = {
      description = "wgmesh coordinator (HTTP + WireGuard hub)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "sshd.service" ];
      wants = [ "network-online.target" ];
      path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.coreutils ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wgmesh-coord -c ${configFile}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "always";
        RestartSec = 5;

        User = "root";
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_SYS_MODULE" ];

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        LockPersonality = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_NETLINK" "AF_UNIX" ];

        ReadWritePaths = [ cfg.stateDir ];
        ReadOnlyPaths = [ cfg.sshKeyPath cfg.authorizedSignersPath ]
          ++ lib.optional (cfg.tlsCert != "") cfg.tlsCert
          ++ lib.optional (cfg.tlsKey != "") cfg.tlsKey;
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ listenPortFromAddr ];
      allowedUDPPorts = [ cfg.wgListenPort ];
    };
  };
}
