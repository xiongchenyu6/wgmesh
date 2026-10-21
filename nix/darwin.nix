# wgmesh on nix-darwin: the same mesh as module.nix, built from wg-quick
# (wireguard-go) and a launchd wgautomesh. A Mac is always a plain node;
# the relay has to be a NixOS host.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) filterAttrs mapAttrsToList mkIf;
  cfg = config.services.wgmesh;
  self = cfg.nodes.${cfg.hostName} or null;
  relay = cfg.nodes.${cfg.relay} or null;
  validNodes = self != null && relay != null;
  wgautomesh = lib.getExe cfg.package;
  wireguard-go = lib.getExe pkgs.wireguard-go;
  settings = (pkgs.formats.toml { }).generate "wgautomesh.toml" {
    inherit (cfg) interface;
    gossip_port = cfg.gossipPort;
    gossip_secret_file = cfg.gossipSecretFile;
    persist_file = "/var/db/wgautomesh.state";
    lan_discovery = true;
    relay_fallback = true;
    peers = mapAttrsToList (
      _: node:
      {
        pubkey = node.publicKey;
        inherit (node) address;
      }
      // lib.optionalAttrs (node.endpoint != null) { inherit (node) endpoint; }
    ) (filterAttrs (name: _: name != cfg.hostName && name != cfg.relay) cfg.nodes);
  };
in
{
  imports = [ ./options.nix ];

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = self != null;
        message = "services.wgmesh.nodes has no entry for this host (${cfg.hostName}).";
      }
      {
        assertion = relay != null && relay.endpoint != null;
        message = "services.wgmesh.relay (${cfg.relay}) must be a node with an endpoint.";
      }
      {
        assertion = cfg.hostName != cfg.relay;
        message = "services.wgmesh: the relay must be a NixOS host.";
      }
    ];

    # wg-quick routes the relay's allowed IPs into the interface, so the /32s
    # that wgautomesh adds on the same interface need no routes of their own.
    networking.wg-quick.interfaces.${cfg.interface} = mkIf validNodes {
      address = [ "${self.address}/32" ];
      inherit (cfg) listenPort privateKeyFile;
      peers = [
        {
          inherit (relay) publicKey endpoint;
          allowedIPs = [ cfg.cidr ] ++ cfg.relayPrefixes;
          persistentKeepalive = 25;
        }
      ];
      autostart = true;
    };

    environment.systemPackages = mkIf validNodes [ pkgs.wireguard-tools ];

    # Only wg-quick maps the interface name to its utun; `wg` itself needs the
    # utun name. A restarted tunnel gets a new utun, wgautomesh then fails on
    # `wg show` and launchd starts it again with the new name.
    launchd.daemons.wgautomesh.serviceConfig = mkIf validNodes {
      ProgramArguments = [
        "/bin/sh"
        "-c"
        ''
          utun=$(cat /var/run/wireguard/${cfg.interface}.name) || exit 1
          sed "s/^interface = .*/interface = \"$utun\"/" ${settings} > /var/run/wgautomesh.toml
          exec ${wgautomesh} /var/run/wgautomesh.toml
        ''
      ];
      EnvironmentVariables = {
        PATH = "${pkgs.wireguard-tools}/bin:/usr/bin:/bin:/usr/sbin:/sbin";
        RUST_LOG = "wgautomesh=info";
      };
      KeepAlive = true;
      RunAtLoad = true;
      StandardErrorPath = "/var/log/wgautomesh.log";
    };

    # The application firewall would drop peers dialing in directly and
    # gossip; both binaries are unsigned store paths.
    system.activationScripts.postActivation.text = mkIf validNodes ''
      fw=/usr/libexec/ApplicationFirewall/socketfilterfw
      for app in ${wireguard-go} ${wgautomesh}; do
        $fw --add "$app" >/dev/null
        $fw --unblockapp "$app" >/dev/null
      done
    '';
  };
}
