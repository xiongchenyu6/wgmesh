# Example NixOS configuration for the coordinator host (a public VPS).
#
# Usage in your flake:
#
#   inputs.wgmesh.url = "github:xiongchenyu6/wgmesh";
#
#   outputs = { self, nixpkgs, wgmesh, ... }: {
#     nixosConfigurations.coord = nixpkgs.lib.nixosSystem {
#       system = "x86_64-linux";
#       modules = [
#         wgmesh.nixosModules.coordinator
#         ./examples/coord-host.nix
#       ];
#     };
#   };

{ pkgs, ... }: {
  # The coordinator's WireGuard keypair is derived from this host key —
  # services.openssh provides /etc/ssh/ssh_host_ed25519_key by default.
  services.openssh.enable = true;

  services.wgmesh-coord = {
    enable                = true;
    meshCidr              = "10.42.0.0/16";
    endpoint              = "vps.example.com:51820";   # public WG UDP host:port
    authorizedSignersPath = "/etc/wgmesh/authorized_signers";
    openFirewall          = true;
    # meshIP             = "10.42.0.1";                 # default = first usable
    # listenAddr         = ":8443";                     # HTTP API (default)
    # wgListenPort       = 51820;                       # WG UDP port (default)
  };

  # Manage authorized_signers with sops-nix in real deployments.
  environment.etc."wgmesh/authorized_signers" = {
    mode = "0644";
    text = ''
      # ssh-ed25519 AAAA... node-a
      # ssh-ed25519 AAAA... node-b
    '';
  };

  services.coturn = {
    enable = true;
    listening-port = 3478;
    no-tls = true; no-dtls = true;
    use-auth-secret = false; no-auth = true;   # STUN-only, no TURN auth
  };
  networking.firewall.allowedUDPPorts = [ 3478 ];
}
