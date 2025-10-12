{
  description = "Flake to fetch https-wrench from xenos76's NUR repo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nur-os76.url = "github:xenos76/nur-packages";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    nur-os76,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };

        https-wrench = pkgs.callPackage (nur-os76 + "/pkgs/https-wrench") {};
      in {
        packages.default = https-wrench;

        devShells.default = pkgs.mkShell {
          name = "HTTPS-Wrench-Demo";
          packages = [
            https-wrench
            pkgs.gum
          ];
          shellHook = ''
            gum format --theme tokyo-night -- "# HTTPS-Wrench Nix shell" "**https-wrench** *version*: \`$(https-wrench --version)\`"
          '';
        };
      }
    );
}
