{
  description = "wgmesh — SSH-keyed WireGuard mesh for NixOS (Rust impl)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
    in
    flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs { inherit system; };
        mkApp = name: {
          type = "app";
          program = "${wgmesh}/bin/${name}";
          meta.description = "wgmesh ${name}";
        };
        wgmesh = pkgs.rustPlatform.buildRustPackage {
          pname = "wgmesh";
          version = "0.1.0";
          src = ./rust;
          cargoLock.lockFile = ./rust/Cargo.lock;

          # Workspace produces these four binaries; --bins is explicit so it's
          # obvious from the flake what ends up in $out/bin.
          cargoBuildFlags = [ "--bins" ];

          # Sanity check: every expected binary made it into $out/bin.
          postInstall = ''
            for bin in wgmesh-coord wgmesh-agent ssh-to-wg wgmesh-smoketest; do
              test -x "$out/bin/$bin" \
                || (echo "wgmesh: missing $bin in $out/bin" >&2; exit 1)
            done
          '';

          # Tests cover pure logic only; the wg-pubkey parity test needs
          # ssh-keygen and wg available in PATH and is gated at runtime.
          doCheck = true;
          nativeCheckInputs = with pkgs; [ openssh wireguard-tools ];

          meta = with pkgs.lib; {
            description = "SSH-keyed WireGuard mesh (coordinator + agent)";
            mainProgram = "wgmesh-coord";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };
      in
      {
        packages = {
          default = wgmesh;
          wgmesh = wgmesh;
        };

        # `nix run .#<name>` for each binary the workspace produces.
        # `nix run .` and `nix run .#default` map to the coordinator.
        apps = {
          default          = mkApp "wgmesh-coord";
          wgmesh-coord     = mkApp "wgmesh-coord";
          wgmesh-agent     = mkApp "wgmesh-agent";
          ssh-to-wg        = mkApp "ssh-to-wg";
          wgmesh-smoketest = mkApp "wgmesh-smoketest";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rust-analyzer
            clippy
            rustfmt
            wireguard-tools
            coturn
            openssh
          ];
        };
      })
    // {
      nixosModules = {
        coordinator = { pkgs, lib, ... }: {
          imports = [ ./nix/coordinator.nix ];
          services.wgmesh-coord.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
        agent = { pkgs, lib, ... }: {
          imports = [ ./nix/agent.nix ];
          services.wgmesh.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
        default = self.nixosModules.agent;
      };
    };
}
