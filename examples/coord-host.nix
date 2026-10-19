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
    # Pin a node's mesh IP in git (IP -> its host pubkey; comment ignored).
    # The key must also be in authorizedSigners.
    # staticIPs = { "10.42.0.10" = "ssh-ed25519 AAAA... node-a"; };
    openFirewall = true;
    # endpointHost = "wg.example.com";   # only if WG host ≠ HTTP host
    # wgListenPort = 51820;              # default
    # meshIP       = "10.42.0.1";        # default = first usable
    # For direct HTTPS, provision these files (otherwise use a TLS reverse proxy):
    # tlsCert = "/run/secrets/mesh-cert.pem";
    # tlsKey  = "/run/secrets/mesh-key.pem";
    # listenAddr   = ":8443";            # default
  };

  # Discovery uses real WG endpoints observed by this hub; no STUN server needed.
}
