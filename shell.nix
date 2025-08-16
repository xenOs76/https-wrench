{pkgs ? import <nixpkgs> {}}: let
  goreleaser-test-release = pkgs.writeShellScriptBin "goreleaser-test-release" ''
    ${pkgs.goreleaser}/bin/goreleaser release --snapshot --clean
  '';
  goreleaser-release = pkgs.writeShellScriptBin "goreleaser-release" ''
    ${pkgs.goreleaser}/bin/goreleaser release --clean
  '';
in
  pkgs.mkShell {
    name = "GithubGoShell";

    packages = with pkgs; [
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
  }
