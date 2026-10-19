{
  description = "wgmesh: kernel-WireGuard full mesh for NixOS from stock modules (wireguard + wgautomesh)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      nixosModules.default = ./nix/module.nix;

      checks = forAllSystems (system: {
        vm = import ./tests/vm.nix {
          pkgs = nixpkgs.legacyPackages.${system};
          module = self.nixosModules.default;
        };
      });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
