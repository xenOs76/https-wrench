{
  description = "GithubGoShell";

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
          name = "GithubGoShell";
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

          shellHook = ''
            echo "Exporting GITHUB_TOKEN...";
            export GITHUB_TOKEN="$(cat ~/.config/goreleaser/github_token)";
          '';
        };
      }
    );
}
