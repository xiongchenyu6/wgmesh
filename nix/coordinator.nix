{ config, lib, pkgs, ... }:

let
  cfg = config.services.wgmesh-coord;

  # Filter out empty/null values so the JSON only carries fields the user
  # actually set; the coord fills in defaults for the rest.
  configAttrs = lib.filterAttrs (n: v: v != null && v != "") {
    listen_addr = cfg.listenAddr;
    tls_cert = cfg.tlsCert;
    tls_key = cfg.tlsKey;
    mesh_cidr = cfg.meshCidr;
    state_path = "${cfg.stateDir}/state.json";
    authorized_signers = cfg.authorizedSignersPath;
    peer_ttl_seconds = cfg.peerTTLSeconds;
    relay_ssh_key = cfg.relay.sshKeyPath;
    relay_interface = cfg.relay.interface;
    relay_listen_port = cfg.relay.listenPort;
    relay_endpoint = cfg.relay.endpoint;
    relay_mesh_ip = cfg.relay.meshIP;
  };
  # relay_enabled is bool — it must always be present so the coord doesn't
  # default-true when the user explicitly disabled the relay.
  configFile = pkgs.writeText "wgmesh-coord.json" (builtins.toJSON
    (configAttrs // { relay_enabled = cfg.relay.enable; }));

  listenPortFromAddr =
    let parts = lib.splitString ":" cfg.listenAddr;
    in lib.toInt (lib.last parts);
in
{
  options.services.wgmesh-coord = {
    enable = lib.mkEnableOption "wgmesh coordinator (HTTP API + relay hub)";

    package = lib.mkOption {
      type = lib.types.package;
      description = "wgmesh package providing the wgmesh-coord binary.";
    };

    listenAddr = lib.mkOption {
      type = lib.types.str;
      default = ":8443";
      description = "HTTP listen address.";
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

    meshCidr = lib.mkOption {
      type = lib.types.str;
      example = "10.42.0.0/16";
      description = "IPv4 CIDR for mesh IP allocation.";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/wgmesh-coord";
      description = "State directory (holds state.json with stable mesh-IP assignments).";
    };

    authorizedSignersPath = lib.mkOption {
      type = lib.types.path;
      example = "/etc/wgmesh/authorized_signers";
      description = "OpenSSH-style ed25519 public key allowlist; SIGHUP reloads.";
    };

    peerTTLSeconds = lib.mkOption {
      type = lib.types.int;
      default = 600;
      description = "Peers absent longer than this are hidden from /peers.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the HTTP listen port in the firewall.";
    };

    relay = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Run the WireGuard relay hub on this host. Required for hub-and-spoke
          fallback when nodes can't establish direct P2P. Set to false only if
          you have an external relay or accept that NAT-blocked pairs cannot
          communicate.
        '';
      };

      sshKeyPath = lib.mkOption {
        type = lib.types.path;
        default = "/etc/ssh/ssh_host_ed25519_key";
        description = "SSH ed25519 host key used to derive the relay's WireGuard keypair.";
      };

      interface = lib.mkOption {
        type = lib.types.str;
        default = "wg0";
        description = "Name of the relay's WireGuard kernel interface.";
      };

      listenPort = lib.mkOption {
        type = lib.types.port;
        default = 51820;
        description = "UDP port the relay's WireGuard listens on.";
      };

      endpoint = lib.mkOption {
        type = lib.types.str;
        example = "vps.example.com:51820";
        description = ''
          Public host:port that agents will use to reach the relay. Must be
          reachable from every mesh node (typically a public DNS name or IP).
        '';
      };

      meshIP = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "10.42.0.1";
        description = ''
          Mesh IP to assign to the relay. Empty means: use the first usable IP
          in meshCidr (e.g. 10.42.0.1 for /16). Hard-coded here so agents can
          rely on it being stable.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.wgmesh-coord = {
      isSystemUser = true;
      group = "wgmesh-coord";
      description = "wgmesh coordinator service user (HTTP only; relay runs as root)";
    };
    users.groups.wgmesh-coord = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 ${if cfg.relay.enable then "root" else "wgmesh-coord"} ${if cfg.relay.enable then "root" else "wgmesh-coord"} -"
    ];

    boot.kernelModules = lib.mkIf cfg.relay.enable [ "wireguard" ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = lib.mkIf cfg.relay.enable 1;

    systemd.services.wgmesh-coord = {
      description = "wgmesh coordinator";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "sshd.service" ];
      wants = [ "network-online.target" ];
      # `wg` and `ip` are shelled out to by the relay; both must be in PATH.
      path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.coreutils ];

      serviceConfig =
        let
          common = {
            ExecStart = "${cfg.package}/bin/wgmesh-coord -c ${configFile}";
            ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
            Restart = "always";
            RestartSec = 5;
            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            ProtectControlGroups = true;
            LockPersonality = true;
            ReadWritePaths = [ cfg.stateDir ];
            ReadOnlyPaths = lib.optional (cfg.authorizedSignersPath != null) cfg.authorizedSignersPath
              ++ lib.optional (cfg.tlsCert != "") cfg.tlsCert
              ++ lib.optional (cfg.tlsKey != "") cfg.tlsKey
              ++ lib.optional cfg.relay.enable cfg.relay.sshKeyPath;
          };
        in
        if cfg.relay.enable then
          common // {
            User = "root";
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_SYS_MODULE" ];
            RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_NETLINK" "AF_UNIX" ];
          }
        else
          common // {
            User = "wgmesh-coord";
            Group = "wgmesh-coord";
            PrivateDevices = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
            RestrictNamespaces = true;
            MemoryDenyWriteExecute = true;
            SystemCallArchitectures = "native";
          };
    };

    networking.firewall = {
      allowedTCPPorts = lib.mkIf cfg.openFirewall [ listenPortFromAddr ];
      allowedUDPPorts = lib.mkIf cfg.relay.enable [ cfg.relay.listenPort ];
    };
  };
}
