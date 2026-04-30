# Example NixOS configuration for the coordinator host (a public VPS).

{ pkgs, ... }: {
  # The coordinator's WireGuard keypair is derived from this host key —
  # services.openssh provides /etc/ssh/ssh_host_ed25519_key by default.
  services.openssh.enable = true;

  # Required: meshCidr + authorizedSigners. Agents will derive the WG
  # hostname from their own `services.wgmesh.coordinator` URL plus the
  # port published in /peers (default 51820), so no endpoint goes here.
  services.wgmesh-coord = {
    enable    = true;
    meshCidr  = "10.42.0.0/16";
    authorizedSigners = [
      # Add a line per node. After a node first boots, grab its pubkey
      # with `ssh node 'cat /etc/ssh/ssh_host_ed25519_key.pub'`, paste it
      # here, then `nixos-rebuild switch` on the coord — reload is
      # automatic (reloadTriggers fires SIGHUP).
      # "ssh-ed25519 AAAA... node-a"
      # "ssh-ed25519 AAAA... node-b"
    ];
    openFirewall = true;
    # endpointHost = "wg.example.com";   # only if WG host ≠ HTTP host
    # wgListenPort = 51820;              # default
    # meshIP       = "10.42.0.1";        # default = first usable
    # listenAddr   = ":8443";            # default
  };

  services.coturn = {
    enable = true;
    listening-port = 3478;
    no-tls = true; no-dtls = true;
    use-auth-secret = false; no-auth = true;   # STUN-only, no TURN auth
  };
  networking.firewall.allowedUDPPorts = [ 3478 ];
}
