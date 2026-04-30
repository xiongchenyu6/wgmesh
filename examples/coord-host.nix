# Example NixOS configuration for the coordinator host (a public VPS).

{ pkgs, ... }: {
  # The coordinator's WireGuard keypair is derived from this host key —
  # services.openssh provides /etc/ssh/ssh_host_ed25519_key by default.
  services.openssh.enable = true;

  # Three required fields. Agents will derive the WG hostname from their own
  # `services.wgmesh.coordinator` URL plus the port published in /peers
  # (default 51820), so no endpoint goes here.
  services.wgmesh-coord = {
    enable                = true;
    meshCidr              = "10.42.0.0/16";
    authorizedSignersPath = "/etc/wgmesh/authorized_signers";
    openFirewall          = true;
    # endpointHost = "wg.example.com";   # only if WG host ≠ HTTP host
    # wgListenPort = 51820;              # default
    # meshIP       = "10.42.0.1";        # default = first usable
    # listenAddr   = ":8443";            # default
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
