{
  description = "GiteaGoShell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    # self,
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };

        goreleaser-test-release = pkgs.writeShellScriptBin "goreleaser-test-release" ''
          ${pkgs.goreleaser}/bin/goreleaser release --snapshot --clean
        '';

        goreleaser-release = pkgs.writeShellScriptBin "goreleaser-release" ''
          ${pkgs.goreleaser}/bin/goreleaser release --clean
        '';
      in {
        devShells.default = pkgs.mkShell {
          name = "GiteaGoShell";
          buildInputs = with pkgs; [
            go
            air
            httpie
            goreleaser
            govulncheck

            jq
            curl
            goreleaser-test-release
            goreleaser-release
          ];

          CGO_ENABLED = 0;
          COMPOSE_BAKE = "true";
          DOCKER_REGISTRY = "registry.0.os76.xyz";
          DOCKER_USER = "xeno";

          shellHook = ''
            echo "Exporting GITEA_TOKEN...";
            export GITEA_TOKEN="$(cat ~/.config/goreleaser/gitea_token)";
          '';
        };
      }
    );
}
