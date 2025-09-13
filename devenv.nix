{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  env = {
    GUM_FORMAT_THEME = "tokyo-night";
    CAROOT = "tests/certs";
    CGO_ENABLE = "0";
    OS76_DOCKER_REGISTRY = "registry.0.os76.xyz";
    OS76_DOCKER_USER = "xeno";
  };

  packages = with pkgs; [
    git
    mkcert
    gum
    goreleaser
    curl
    jq
    httpie
  ];

  git-hooks = {
    excludes = [
      "devenv.nix"
      "flake.nix"
      ".gitignore"
      ".envrc"
    ];
    hooks = {
      shellcheck.enable = true;
      end-of-file-fixer.enable = true;
      detect-aws-credentials.enable = false;
      detect-private-keys.enable = true;
      ripsecrets.enable = true;
      commitizen.enable = true;
    };
  };

  languages.go.enable = true;

  services.nginx = {
    enable = true;
    httpConfig = ''
      #
      # Mozilla SSL Configuration Generator
      #
      # https://ssl-config.mozilla.org/#server=nginx&version=1.27.3&config=intermediate&openssl=3.4.0&guideline=5.7
      #
      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_ecdh_curve X25519:prime256v1:secp384r1;
      ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
      ssl_prefer_server_ciphers off;

      # see also ssl_session_ticket_key alternative to stateful session cache
      ssl_session_timeout 1d;
      ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions

      # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
      ssl_dhparam "${config.env.DEVENV_ROOT}/${config.env.CAROOT}/dhparam";
      ssl_certificate ${config.env.DEVENV_ROOT}/${config.env.CAROOT}/full-cert.pem;
      ssl_certificate_key ${config.env.DEVENV_ROOT}/${config.env.CAROOT}/key.pem;

      server {
          server_name  _;

          root ${config.env.DEVENV_ROOT};

          listen 9443 ssl;
          listen [::]:9443 ssl;
          http2 on;

          location / {
              proxy_pass       http://localhost:8080;
              proxy_set_header Host $host;
              proxy_set_header X-Forwarded-For $remote_addr;
          }
      }

      server {
          server_name  example.com;

          root ${config.env.DEVENV_ROOT};

          listen 9444 ssl proxy_protocol;
          listen [::]:9444 ssl proxy_protocol;

          # http2 on;
          location / {
              proxy_pass       http://localhost:8080;
              proxy_pass_request_headers on;
              proxy_set_header Host $host;
              proxy_set_header X-Proxy-Protocol enabled;
              proxy_set_header X-Proxy-Protocol-Addr       $proxy_protocol_addr;
              proxy_set_header X-Proxy-Protocol-Port       $proxy_protocol_port;
              proxy_set_header X-Forwarded-For $proxy_protocol_addr;
          }
      }
    '';
  };

  services.httpbin = {
    enable = true;
  };

  scripts.hello.exec = ''
    gum format "# Devenv shell"
  '';

  scripts.goreleaser-test-release.exec = ''
    ${pkgs.goreleaser}/bin/goreleaser release --snapshot --clean
  '';

  scripts.goreleaser-release.exec = ''
    ${pkgs.goreleaser}/bin/goreleaser release --clean
  '';

  scripts.create-certs.exec = ''
    test -f $CAROOT/dhparam || curl https://ssl-config.mozilla.org/ffdhe2048.txt > $CAROOT/dhparam
    test -d $CAROOT || mkdir -p $CAROOT
    test -d $CAROOT/cert.pem || mkcert -key-file $CAROOT/key.pem -cert-file $CAROOT/cert.pem localhost 127.0.0.1 example.com *.example.com
    test -d $CAROOT/full-cert.pem || cat  $CAROOT/cert.pem $CAROOT/rootCA.pem > $CAROOT/full-cert.pem
  '';

  scripts.build.exec = ''
    gum format "## building..."
    ./build.sh
  '';

  scripts.test-curl.exec = ''
    curl "https://localhost:9443/get" -k -v
  '';

  scripts.test-sample-config.exec = ''
    gum format "## test request with sample config"
    ./dist/https-wrench requests --config ./src/cmd/embedded/config-example.yaml
  '';

  scripts.test-k3s.exec = ''
    gum format "## test request against local k3s"
    ./dist/https-wrench requests --config ./examples/https-wrench-k3s.yaml
  '';

  scripts.test-timeout.exec = ''
    gum format "## test request timeout"
    ./dist/https-wrench requests --config ./examples/https-wrench-request-timeout.yaml | grep "Client.Timeout exceeded while awaiting headers"
  '';

  scripts.test-unknown-ca.exec = ''
    gum format "## test request with unknown CA"

    set +o pipefail
    ./dist/https-wrench requests --config ./examples/tests-configs/unknown-ca.yaml | grep 'failed to verify certificate: x509: certificate signed by unknown authority'
  '';

  scripts.test-insecure.exec = ''
    gum format "## test insecure skip verify"
    ./dist/https-wrench requests --config ./examples/tests-configs/insecure.yaml | grep 'StatusCode: 200'
  '';

  scripts.test-body-regexp-match.exec = ''
    gum format "## test body regexp match"
    ./dist/https-wrench requests --config  ./examples/tests-configs/body-regexp-match.yaml  --ca-bundle $CAROOT/rootCA.pem | grep 'BodyRegexpMatch: true'
  '';

  scripts.test-ca-bundle-file-success.exec = ''
    gum format "## test request with CA bundle file"
    ./dist/https-wrench requests --config ./examples/tests-configs/ca-bundle-200.yaml --ca-bundle $CAROOT/rootCA.pem | grep "StatusCode: 200"
  '';

  scripts.test-ca-bundle-file-wrong-servername.exec = ''
    gum format "## test request with CA bundle file and wrong host name / servername"
    ./dist/https-wrench requests --config ./examples/tests-configs/ca-bundle-wrong-servername.yaml --ca-bundle $CAROOT/rootCA.pem | grep 'tls: failed to verify certificate: x509'
  '';

  scripts.test-proxy-protocol-ipv4.exec = ''
    gum format "## test proxy protocol IPv4"
    ./dist/https-wrench requests --config ./examples/tests-configs/proxy-protocol-ipv4.yaml --ca-bundle $CAROOT/rootCA.pem | grep '192.0.2.1'
  '';

  scripts.test-proxy-protocol-ipv6.exec = ''
    gum format "## test proxy protocol IPv6"
    ./dist/https-wrench requests --config ./examples/tests-configs/proxy-protocol-ipv6.yaml --ca-bundle $CAROOT/rootCA.pem | grep '2001:db8::1'
  '';

  scripts.test-ca-bundle-yaml.exec = ''
    gum format "## test request with CA bundle in YAML"

    CA_BUNDLE_YAML_TEST_FILE=./tests/https-wrench-tests-ca-bundle-string.yaml

    cat ./examples/tests-configs/unknown-ca.yaml > $CA_BUNDLE_YAML_TEST_FILE

    echo "caBundle: |" >> $CA_BUNDLE_YAML_TEST_FILE
    while IFS= read -r line; do echo  "  $line" >> $CA_BUNDLE_YAML_TEST_FILE ; done < $CAROOT/rootCA.pem

    ./dist/https-wrench requests --config $CA_BUNDLE_YAML_TEST_FILE | grep 'StatusCode: 200'
  '';

  enterShell = ''
    gum format "# Devenv shell"
    export GITEA_TOKEN=$(cat ~/.config/goreleaser/gitea_token)
    export GITHUB_TOKEN=$(cat ~/.config/goreleaser/github_token)
    go version
    create-certs
  '';

  enterTest = ''
    gum format "# Running tests"
    build
    test-sample-config
    test-k3s
    test-timeout
    test-insecure
    test-unknown-ca
    test-ca-bundle-file-success
    test-ca-bundle-file-wrong-servername
    test-proxy-protocol-ipv4
    test-proxy-protocol-ipv6
    test-ca-bundle-yaml
    test-body-regexp-match
  '';
}
