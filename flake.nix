{
  description = "device-ca: certificate authority for the local.yawk.at network";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        server = pkgs.callPackage ./nix/package.nix { };
        cert-request = pkgs.callPackage ./nix/cert-request.nix { };
        default = server;
      });

      overlays.default = final: _prev: {
        cert-request = final.callPackage ./nix/cert-request.nix { };
      };

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAllSystems (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) server cert-request;
        nixos = pkgs.callPackage ./nix/nixos-test.nix { inherit self; };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.server ];
          packages = [
            pkgs.jdk21
            self.packages.${pkgs.stdenv.hostPlatform.system}.server.gradle
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
