{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  env.GUM_FORMAT_THEME = "tokyo-night";
  env.TEST_DIR = "tests";
  env.CAROOT = "tests/certs";

  packages = with pkgs; [
    git
    mkcert
    gum
  ];

  # git-hooks.hooks.shellcheck.enable = true;

  languages.go.enable = true;

  services.httpbin = {
    enable = true;
    extraArgs = [
      "--keyfile"
      "tests/certs/key.pem"
      "--certfile"
      "tests/certs/cert.pem"
      "--ca-certs"
      "tests/certs/rootCA.pem"
    ];
  };

  scripts.hello.exec = ''
    gum format "# Devenv shell"
  '';

  scripts.create-certs.exec = ''
    gum format "## creating certs"
    test -d $CAROOT || mkdir -p $CAROOT && mkcert -key-file $CAROOT/key.pem -cert-file $CAROOT/cert.pem localhost 127.0.0.1 example.com *.example.com
  '';

  scripts.build.exec = ''
    gum format "## building..."
    ./build.sh
  '';

  scripts.test-sample-config.exec = ''
    gum format "## test request with sample config"

    ./dist/https-wrench requests --config ./src/cmd/embedded/config-example.yaml
  '';

  scripts.test-k3s.exec = ''
    gum format "## test request against local k3s"

    ./dist/https-wrench requests --config ./examples/https-wrench-k3s.yaml
  '';

  scripts.test-unknown-ca.exec = ''
    gum format "## test request with unknown CA"

    set +o pipefail
    ./dist/https-wrench requests --config ./examples/https-wrench-tests.yaml | grep 'failed to verify certificate: x509: certificate signed by unknown authority'
  '';

  scripts.test-ca-bundle-file.exec = ''
    gum format "## test request with CA bundle file"

    CMD='./dist/https-wrench requests --config ./examples/https-wrench-tests.yaml  --ca-bundle ./tests/certs/rootCA.pem | grep "StatusCode: 200"'

    echo "Running: $CMD"

    $CMD
  '';

  enterShell = ''
    go version
    test -d $CAROOT || create-certs
  '';

  enterTest = ''
    gum format "# Running tests"
    build
    test-sample-config
    test-k3s
    test-unknown-ca
    test-ca-bundle-file
  '';
}
