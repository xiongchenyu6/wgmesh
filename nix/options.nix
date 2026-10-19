# Options shared by the NixOS module (module.nix) and the nix-darwin one (darwin.nix).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkEnableOption mkOption types;
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
}
