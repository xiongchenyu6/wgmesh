# Example NixOS configuration for the coordinator host (a public VPS).
#
# Usage in your flake:
#
#   inputs.wgmesh.url = "github:freemanxiong/wgmesh";   # adjust
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
  services.openssh.enable = true;     # for /etc/ssh/ssh_host_ed25519_key (used by relay)

  services.wgmesh-coord = {
    enable = true;
    listenAddr = ":8443";
    meshCidr = "10.42.0.0/16";
    authorizedSignersPath = "/etc/wgmesh/authorized_signers";
    openFirewall = true;

    relay = {
      enable = true;
      endpoint = "vps.example.com:51820";   # public host:port; agents connect here for the WG hub
      # meshIP = "10.42.0.1";               # default = first usable in meshCidr
    };
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
