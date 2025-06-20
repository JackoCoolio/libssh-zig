{
  description = "";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      perSystem =
        {
          self',
          inputs',
          pkgs,
          ...
        }:
        {
          packages.default = pkgs.stdenvNoCC.mkDerivation {
            name = "ssh-zig";

            src = ./.;

            nativeBuildInputs = [inputs'.zig-overlay.packages."0.16.0"];
          };

          devShells.default = pkgs.mkShellNoCC {
            inputsFrom = [self'.packages.default];
            packages = [
              inputs'.zls.packages.default
            ];
          };

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
