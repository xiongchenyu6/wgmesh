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
  ...
}:
let
  inherit (lib) filterAttrs mapAttrsToList mkIf;
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
  imports = [ ./options.nix ];

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
