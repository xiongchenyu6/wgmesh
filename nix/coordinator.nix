{ config, lib, pkgs, ... }:

let
  cfg = config.services.wgmesh-coord;

  # Allowlist file location is internal — declared by `authorizedSigners` /
  # `authorizedSignerFiles` and rendered by this module. Not user-overridable.
  signersFile = "/etc/wgmesh/authorized_signers";

  # The coordinator always runs the WG hub (it's both an HTTP server *and*
  # a WireGuard peer with every agent). Field naming reflects that — no
  # `relay` jargon, just plain "wg" since WireGuard is the only data path.
  configAttrs = lib.filterAttrs (n: v: v != null && v != "") {
    listen_addr        = cfg.listenAddr;
    tls_cert           = cfg.tlsCert;
    tls_key            = cfg.tlsKey;
    mesh_cidr          = cfg.meshCidr;
    state_path         = "${cfg.stateDir}/state.json";
    authorized_signers = signersFile;
    peer_ttl_seconds   = cfg.peerTTLSeconds;
    wg_ssh_key         = cfg.sshKeyPath;
    wg_interface       = cfg.interface;
    wg_listen_port     = cfg.wgListenPort;
    wg_endpoint_host   = cfg.endpointHost;
    wg_mesh_ip         = cfg.meshIP;
  };
  configFile = pkgs.writeText "wgmesh-coord.json" (builtins.toJSON configAttrs);

  # Declarative allowlist: inline strings + files concatenated. Rendered
  # to signersFile via environment.etc; reloadTriggers carries the hash.
  fromList  = lib.concatStringsSep "\n" cfg.authorizedSigners;
  fromFiles = lib.concatMapStringsSep "\n"
    (f: lib.removeSuffix "\n" (builtins.readFile f))
    cfg.authorizedSignerFiles;
  renderedSigners =
    let parts = lib.filter (s: s != "") [ fromList fromFiles ];
    in if parts == [] then "" else (lib.concatStringsSep "\n" parts) + "\n";

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

    authorizedSigners = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...AAA node-a"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...BBB node-b"
      ];
      description = ''
        Inline OpenSSH ed25519 public key lines authorizing nodes to join
        the mesh. Concatenated with `authorizedSignerFiles` and rendered
        to `/etc/wgmesh/authorized_signers` declaratively. Changing this
        list automatically reloads the coord on activation (SIGHUP via
        `systemd.services.wgmesh-coord.reloadTriggers`); no manual step.
      '';
    };

    authorizedSignerFiles = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [];
      example = lib.literalExpression ''[ ./pubkeys/node-a.pub ./pubkeys/node-b.pub ]'';
      description = ''
        Paths to OpenSSH `.pub` files; their contents are concatenated
        with `authorizedSigners` into the rendered allowlist. Useful when
        per-node pubkeys live in their own files in the flake.
      '';
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
    # The allowlist file is always declared — even when both lists are
    # empty (first-bootstrap state, before any agent pubkeys are pasted in).
    # Coord starts, accepts no requests until the lists grow, then a
    # subsequent `nixos-rebuild` triggers SIGHUP via reloadTriggers.
    environment.etc."wgmesh/authorized_signers" = {
      mode = "0644";
      text = ''
        # wgmesh authorized signers — managed by NixOS.
        # Source of truth: services.wgmesh-coord.authorizedSigners
        #                  services.wgmesh-coord.authorizedSignerFiles
        # Edit those options in your flake; do NOT edit this file by hand.
      '' + renderedSigners;
    };

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

      # Rebuild + activate → if the JSON config or the rendered allowlist
      # changed, systemd fires ExecReload (SIGHUP). No manual reload step.
      reloadTriggers = [ configFile renderedSigners ];

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
        ReadOnlyPaths = [ cfg.sshKeyPath signersFile ]
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
