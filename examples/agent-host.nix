# Example NixOS configuration for a mesh node (any host, NAT or public).
#
# Drop this into a NixOS system that imports the wgmesh agent module.

{ ... }: {
  services.openssh.enable = true; # ensures /etc/ssh/ssh_host_ed25519_key exists

  services.wgmesh = {
    enable = true;
    coordinator = "https://mesh.example.com:8443";
    stunServer = "stun.example.com:3478";
    interface = "wg0";
    listenPort = 51820;
    includeLAN = true;
  };
}
