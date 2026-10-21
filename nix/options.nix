# Options shared by the NixOS module (module.nix) and the nix-darwin one (darwin.nix).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.wgmesh;

  parseIPv4 =
    value:
    let
      parts = builtins.match "^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$" value;
      octets = if parts == null then [ ] else map lib.toInt parts;
    in
    if parts != null && lib.all (octet: octet <= 255) octets then octets else null;

  ipv4ToInt = octets: builtins.foldl' (value: octet: value * 256 + octet) 0 octets;
  pow2 = exponent: if exponent == 0 then 1 else 2 * pow2 (exponent - 1);

  parseCIDR =
    value:
    let
      parts = builtins.match "^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)/([0-9]+)$" value;
      address = if parts == null then null else parseIPv4 (builtins.elemAt parts 0);
      prefixLength = if parts == null then null else lib.toInt (builtins.elemAt parts 1);
    in
    if parts != null && address != null && prefixLength >= 0 && prefixLength <= 32 then
      {
        inherit address prefixLength;
        mask = if prefixLength == 0 then 0 else pow2 32 - pow2 (32 - prefixLength);
      }
    else
      null;

  cidr = parseCIDR cfg.cidr;
  nodeAddresses = map (node: parseIPv4 node.address) (builtins.attrValues cfg.nodes);
  nodeAddressInts = map ipv4ToInt (lib.filter (address: address != null) nodeAddresses);
  addressesInCIDR =
    address:
    if address == null || cidr == null then
      false
    else
      let
        addressInt = ipv4ToInt address;
      in
      builtins.bitAnd addressInt cidr.mask == builtins.bitAnd (ipv4ToInt cidr.address) cidr.mask;
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

    gossipPort = mkOption {
      type = types.port;
      default = 1666;
      description = "UDP port used for encrypted endpoint gossip; it is opened in the firewall.";
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
        assertion = cidr != null;
        message = "services.wgmesh.cidr must be a valid IPv4 CIDR.";
      }
      {
        assertion = lib.all (address: address != null) nodeAddresses;
        message = "Every services.wgmesh.nodes.<name>.address must be a valid IPv4 address.";
      }
      {
        assertion = lib.length nodeAddressInts == lib.length (lib.unique nodeAddressInts);
        message = "services.wgmesh.nodes must not contain duplicate IPv4 addresses.";
      }
      {
        assertion = cidr != null && lib.all addressesInCIDR nodeAddresses;
        message = "Every services.wgmesh.nodes.<name>.address must be inside services.wgmesh.cidr.";
      }
      {
        assertion = lib.all (prefix: parseCIDR prefix != null) cfg.relayPrefixes;
        message = "Every services.wgmesh.relayPrefixes entry must be a valid IPv4 CIDR.";
      }
    ];
  };
}
