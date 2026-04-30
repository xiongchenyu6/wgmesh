{ config, lib, pkgs, ... }:

let
  cfg = config.services.wgmesh;
in
{
  options.services.wgmesh = {
    enable = lib.mkEnableOption "wgmesh node agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = "wgmesh package providing the wgmesh-agent binary.";
    };

    coordinator = lib.mkOption {
      type = lib.types.str;
      example = "https://mesh.example.com";
      description = "Base URL of the wgmesh coordinator.";
    };

    stunServer = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "stun.example.com:3478";
      description = ''
        STUN server (host:port) used to discover the public UDP mapping for the
        WG listen port. Leave empty to skip STUN (only LAN endpoints will be
        advertised).
      '';
    };

    interface = lib.mkOption {
      type = lib.types.str;
      default = "wg0";
      description = "Name of the WireGuard kernel interface managed by the agent.";
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 51820;
      description = "UDP port WireGuard listens on.";
    };

    pollSeconds = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Coordinator poll interval in seconds.";
    };

    sshKeyPath = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = ''
        Path to the OpenSSH ed25519 private key used both for signing
        coordinator requests and for deriving the WireGuard private key.
        Must be readable only by root (the default for sshd host keys).
      '';
    };

    includeLAN = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Include LAN/private addresses in registration so peers on the same subnet can connect directly.";
    };

    skipInterfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "docker0" "lo" ];
      description = "Interface names to ignore when collecting LAN endpoints.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open the WG UDP port in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.coordinator != "";
        message = "services.wgmesh.coordinator must be set.";
      }
    ];

    boot.kernelModules = [ "wireguard" ];
    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.listenPort ];

    systemd.services.wgmesh-agent = {
      description = "wgmesh node agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "sshd.service" ];
      wants = [ "network-online.target" ];

      # The agent shells out to `wg` and `ip` to manage wg0; both must be in PATH.
      path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.coreutils ];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " ([
          "${cfg.package}/bin/wgmesh-agent"
          "--coordinator ${lib.escapeShellArg cfg.coordinator}"
          "--interface ${cfg.interface}"
          "--listen-port ${toString cfg.listenPort}"
          "--poll-secs ${toString cfg.pollSeconds}"
          "--ssh-key ${cfg.sshKeyPath}"
        ]
        ++ lib.optional (cfg.stunServer != "") "--stun ${lib.escapeShellArg cfg.stunServer}"
        ++ lib.optional cfg.includeLAN "--include-lan"
        ++ lib.optional (cfg.skipInterfaces != [])
            "--skip-iface ${lib.escapeShellArg (lib.concatStringsSep "," cfg.skipInterfaces)}"
        );

        Restart = "always";
        RestartSec = 5;

        # Privileges. Run as root so we can manage wg + ip addr/link.
        # NoNewPrivileges still works for root and prevents setuid escalation.
        User = "root";
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_SYS_MODULE" ];

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = false; # may need to load wireguard module
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_NETLINK" "AF_UNIX" ];
        ReadOnlyPaths = [ cfg.sshKeyPath ];
      };
    };

    # Helpful debug commands in $PATH.
    environment.systemPackages = [ cfg.package pkgs.wireguard-tools ];
  };
}
