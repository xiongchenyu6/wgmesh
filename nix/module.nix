# wgmesh: a kernel-WireGuard full mesh for NixOS built only from stock modules.
#
# - networking.wireguard creates the interface and the one static peer: the
#   relay, which carries the whole mesh prefix.
# - wgautomesh (patched with relay_fallback) adds every other node as a /32
#   peer, learns endpoints by gossip and LAN broadcast and punches through NAT.
#   A node only gets its /32 while its handshake is fresh, so pairs that cannot
#   reach each other directly keep talking through the relay.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    filterAttrs
    mapAttrsToList
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.wgmesh;
  self = cfg.nodes.${cfg.hostName};
  relay = cfg.nodes.${cfg.relay};
  isRelay = cfg.hostName == cfg.relay;
  prefixLength = lib.last (lib.splitString "/" cfg.cidr);
  # The relay meshes with everyone; the others leave the relay to
  # networking.wireguard so wgautomesh never narrows its prefix to a /32.
  gossipPeers = filterAttrs (
    name: _: name != cfg.hostName && (isRelay || name != cfg.relay)
  ) cfg.nodes;
in
{
  options.services.wgmesh = {
    enable = mkEnableOption "the wgmesh WireGuard mesh";

    package = mkOption {
      type = types.package;
      default = pkgs.wgautomesh.overrideAttrs (old: {
        patches = (old.patches or [ ]) ++ [ ./wgautomesh-relay-fallback.patch ];
      });
      defaultText = lib.literalMD "`pkgs.wgautomesh` with the relay-fallback patch";
      description = "wgautomesh build; it must understand the `relay_fallback` setting.";
    };

    hostName = mkOption {
      type = types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
      description = "This host's key in `nodes`.";
    };

    interface = mkOption {
      type = types.str;
      default = "wgmesh";
      description = "WireGuard interface name.";
    };

    listenPort = mkOption {
      type = types.port;
      default = 51820;
      description = "WireGuard UDP port; it is opened in the firewall.";
    };

    cidr = mkOption {
      type = types.str;
      example = "10.42.0.0/24";
      description = "Mesh prefix. Every node address lies inside it and the relay routes all of it.";
    };

    relay = mkOption {
      type = types.str;
      description = "Name of the publicly reachable node that forwards traffic between nodes that cannot connect directly.";
    };

    relayPrefixes = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "172.20.0.0/14" ];
      description = "Prefixes outside the mesh that the other nodes route through the relay, such as a network the relay is a gateway to.";
    };

    privateKeyFile = mkOption {
      type = types.path;
      description = "File holding this host's WireGuard private key.";
    };

    gossipSecretFile = mkOption {
      type = types.path;
      description = "File holding the secret shared by all nodes to encrypt gossip.";
    };

    nodes = mkOption {
      description = "Every node in the mesh, including this host.";
      type = types.attrsOf (
        types.submodule {
          options = {
            address = mkOption {
              type = types.str;
              example = "10.42.0.20";
              description = "Mesh IPv4 address.";
            };
            publicKey = mkOption {
              type = types.str;
              description = "WireGuard public key.";
            };
            endpoint = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "203.0.113.1:51820";
              description = "Bootstrap endpoint. Required for the relay; optional for the rest, which are found by gossip.";
            };
          };
        }
      );
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.nodes ? ${cfg.hostName};
        message = "services.wgmesh.nodes has no entry for this host (${cfg.hostName}).";
      }
      {
        assertion = cfg.nodes ? ${cfg.relay} && relay.endpoint != null;
        message = "services.wgmesh.relay (${cfg.relay}) must be a node with an endpoint.";
      }
    ];

    networking.wireguard.interfaces.${cfg.interface} = {
      ips = [ "${self.address}/${prefixLength}" ];
      inherit (cfg) listenPort privateKeyFile;
      peers = lib.optional (!isRelay) {
        inherit (relay) publicKey endpoint;
        allowedIPs = [ cfg.cidr ] ++ cfg.relayPrefixes;
        persistentKeepalive = 25;
      };
    };

    networking.firewall.allowedUDPPorts = [ cfg.listenPort ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = mkIf isRelay (lib.mkDefault 1);

    services.wgautomesh = {
      enable = true;
      inherit (cfg) gossipSecretFile;
      settings = {
        inherit (cfg) interface;
        relay_fallback = !isRelay;
        peers = mapAttrsToList (_: node: {
          pubkey = node.publicKey;
          inherit (node) address endpoint;
        }) gossipPeers;
      };
    };

    systemd.services.wgautomesh = {
      # The stock unit runs pkgs.wgautomesh; with gossip encryption on, its
      # rendered config always lives at this runtime path.
      serviceConfig.ExecStart = lib.mkForce "${lib.getExe cfg.package} /run/wgautomesh/wgautomesh.toml";
      # The device unit exists whichever backend (scripted or networkd)
      # networking.wireguard uses to create the interface.
      bindsTo = [ "sys-subsystem-net-devices-${cfg.interface}.device" ];
      after = [ "sys-subsystem-net-devices-${cfg.interface}.device" ];
    };
  };
}
