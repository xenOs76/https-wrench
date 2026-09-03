{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:
let
  pkgs-stable = import inputs.nixpkgs-stable { system = pkgs.stdenv.system; };
in
{
  env = {
    GUM_FORMAT_THEME = "tokyo-night";
    CAROOT = "tests/certs";
    EXAMPLES = "assets/examples";
    ED25519_DIR = "tests/certs/ed25519_cert";
    ECDSA_DIR = "tests/certs/ecdsa-cert";
    MLDSA_DIR = "tests/certs/mldsa-cert";
    KEY_TEST_PW = "testpassword";
    CGO_ENABLE = "0";
    OS76_DOCKER_REGISTRY = "registry.0.os76.xyz";
    OS76_DOCKER_USER = "xeno";
  };

  # WARN installing go from NixOs stable instead
  # so the version is aligned with nvim settings
  # languages.go = {
  #   enable = true;
  #   package = pkgs-stable.go;
  # };

  packages = with pkgs; [
    pkgs-stable.go
    git
    openssl
    mkcert
    gum
    goreleaser
    govulncheck
    gotest
    gotests
    curl
    jq
    httpie
  ];

  # git-hooks = {
  #   excludes = [
  #     "devenv.nix"
  #     "flake.nix"
  #     ".gitignore"
  #     ".envrc"
  #     "internal/certinfo/common_handlers.go"
  #     "internal/certinfo/testdata"
  #     "internal/jwtinfo/testdata"
  #     "internal/jwtinfo/jwtinfo_test.go"
  #     "internal/certinfo/testdata/README.md"
  #     "completions"
  #   ];
  #   hooks = {
  #     shellcheck.enable = true;
  #     end-of-file-fixer.enable = true;
  #     detect-aws-credentials.enable = false;
  #     detect-private-keys.enable = false;
  #     ripsecrets.enable = true;
  #     commitizen.enable = true;
  #   };
  # };
  #
  services.nginx = {
    enable = true;
    httpConfig = ''

        default_type  application/octet-stream;

        types {
            application/x-yaml yaml;
            text/yaml yaml;
        }

        #
        # Mozilla SSL Configuration Generator
        #
        # generated 2026-09-01, TLSRef Guideline v6.0, nginx 1.27.3, OpenSSL 4.0.1, intermediate config, HSTS, gitrev=d96f668
        # https://configurator.tlsref.org/#server=nginx&version=1.27.3&config=intermediate&openssl=4.0.1&hsts&guideline=6.0
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers off;
        ssl_certificate ${config.env.DEVENV_ROOT}/${config.env.CAROOT}/full-cert.pem;
        ssl_certificate_key ${config.env.DEVENV_ROOT}/${config.env.CAROOT}/key.pem;

        # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
        ssl_dhparam "${config.env.DEVENV_ROOT}/${config.env.CAROOT}/dhparam";

        server {
            server_name  _;
            root ${config.env.DEVENV_ROOT};
            listen 9443 ssl;
            listen [::]:9443 ssl;
            http2 on;
            location / {
                proxy_pass       http://localhost:8080;
                proxy_set_header Host                   $host;
                proxy_set_header X-Forwarded-For        $remote_addr;
            }
            location /tests/ {
                alias ${config.env.DEVENV_ROOT}/${config.env.EXAMPLES}/body-types/;
            }
        }

        server {
            server_name  example.com;
            root ${config.env.DEVENV_ROOT};
            listen 9444 ssl proxy_protocol;
            listen [::]:9444 ssl proxy_protocol;
            http2 on;
            location / {
                proxy_pass                  http://localhost:8080;
                proxy_pass_request_headers  on;
                proxy_set_header            Host $host;
                proxy_set_header            X-Proxy-Protocol        enabled;
                proxy_set_header            X-Proxy-Protocol-Addr   $proxy_protocol_addr;
                proxy_set_header            X-Proxy-Protocol-Port   $proxy_protocol_port;
                proxy_set_header            X-Forwarded-For         $proxy_protocol_addr;
            }
        }

        server {
            server_name  _;
            root ${config.env.DEVENV_ROOT};
            ssl_certificate ${config.env.DEVENV_ROOT}/${config.env.ED25519_DIR}/ed25519.crt;
            ssl_certificate_key ${config.env.DEVENV_ROOT}/${config.env.ED25519_DIR}/ed25519.key;
            listen 9445 ssl;
            listen [::]:9445 ssl;
            http2 on;
            location / {
                proxy_pass       http://localhost:8080;
                proxy_set_header Host                   $host;
                proxy_set_header X-Forwarded-For        $remote_addr;
            }
        }

      server {
            server_name  _;
            root ${config.env.DEVENV_ROOT};
            listen 9446 ssl;
            ssl_certificate ${config.env.DEVENV_ROOT}/${config.env.ECDSA_DIR}/ecdsa.crt;
            ssl_certificate_key ${config.env.DEVENV_ROOT}/${config.env.ECDSA_DIR}/ecdsa.key;
            listen [::]:9446 ssl;
            http2 on;
            location / {
                proxy_pass       http://localhost:8080;
                proxy_set_header Host                   $host;
                proxy_set_header X-Forwarded-For        $remote_addr;
            }
        }

        server {
            server_name  _;
            root ${config.env.DEVENV_ROOT};
            ssl_certificate ${config.env.DEVENV_ROOT}/${config.env.MLDSA_DIR}/mldsa.crt;
            ssl_certificate_key ${config.env.DEVENV_ROOT}/${config.env.MLDSA_DIR}/mldsa.key;
            listen 9447 ssl;
            listen [::]:9447 ssl;
            http2 on;
            location / {
                proxy_pass       http://localhost:8080;
                proxy_set_header Host                   $host;
                proxy_set_header X-Forwarded-For        $remote_addr;
            }
        }
    '';
  };

  services.httpbin = {
    enable = true;
  };

  tasks."web:refreshCertsBeforeNginxStart" = {
    exec = ''
      test -d ${config.env.DEVENV_ROOT}/tests && rm -rf ${config.env.DEVENV_ROOT}/tests
      create-certs
    '';
    before = [ "devenv:processes:nginx" ];
  };

  scripts.hello.exec = ''
    gum format "# Devenv shell"
  '';

  scripts.update-go-deps.exec = ''
    gum format "## updating Go dependencies..."
    go get -u
    gum format "## running go mod tidy..."
    go mod tidy
    gum format "## running go mod vendor..."
    go mod vendor
    gum format "## running govulncheck..."
    govulncheck ./...
  '';

  scripts.build.exec = ''
    set -e
    gum format "## building..."
    go mod vendor
    test -d dist || mkdir dist
    APP_VERSION=$(git describe --tags || echo '0.0.0') &&
        GO_MODULE_NAME=$(go list -m) &&
        CGO_ENABLED=0 go build -o ./dist/https-wrench -ldflags "-X $GO_MODULE_NAME/internal/cmd.version=$APP_VERSION" main.go
  '';

  scripts.goreleaser-test-release.exec = ''
    ${pkgs.goreleaser}/bin/goreleaser release --snapshot --clean
  '';

  scripts.goreleaser-release.exec = ''
    ${pkgs.goreleaser}/bin/goreleaser release --clean
  '';

  scripts.create-certs.exec = ''
    test -d $CAROOT || mkdir -p $CAROOT
    test -f $CAROOT/dhparam || curl https://ssl-config.mozilla.org/ffdhe2048.txt > $CAROOT/dhparam
    test -f $CAROOT/cert.pem || mkcert -key-file $CAROOT/key.pem -cert-file $CAROOT/cert.pem localhost 127.0.0.1 ::1 example.com *.example.com
    test -f $CAROOT/full-cert.pem || cat  $CAROOT/cert.pem $CAROOT/rootCA.pem > $CAROOT/full-cert.pem
    test -f $CAROOT/key.pub || openssl rsa -in $CAROOT/key.pem -pubout -out $CAROOT/key.pub

    test -f $CAROOT/rsa-private_traditional.key || openssl rsa -in $CAROOT/key.pem -traditional -out $CAROOT/rsa-private_traditional.key
    test -f $CAROOT/rsa-private_traditional.pub || openssl rsa -in $CAROOT/rsa-private_traditional.key -pubout -out $CAROOT/rsa-private_traditional.pub

    test -f $CAROOT/rsa-private_traditional_encrypted.key ||  openssl rsa -passout pass:$KEY_TEST_PW -in $CAROOT/rsa-private_traditional.key -out $CAROOT/rsa-private_traditional_encrypted.key -aes256
    test -f $CAROOT/rsa-private_traditional_encrypted.pub || openssl rsa -passin pass:$KEY_TEST_PW -in $CAROOT/rsa-private_traditional_encrypted.key -pubout -out $CAROOT/rsa-private_traditional_encrypted.pub

    test -f $CAROOT/private.ec.key || openssl ecparam -name prime256v1 -genkey -noout -out $CAROOT/private.ec.key
    test -f $CAROOT/private.ec.pub || openssl ec -in $CAROOT/private.ec.key -pubout -out $CAROOT/private.ec.pub

    test -f $CAROOT/encrypted.rsa.key || openssl genrsa -aes128 -passout pass:$KEY_TEST_PW -out $CAROOT/encrypted.rsa.key 4096
    test -f $CAROOT/encrypted.rsa.pub || openssl rsa -passin pass:$KEY_TEST_PW -in $CAROOT/encrypted.rsa.key -pubout -out $CAROOT/encrypted.rsa.pub

    # ECDSA_DIR=$CAROOT/ecdsa-cert
    test -d $ECDSA_DIR || mkdir $ECDSA_DIR
    test -f $ECDSA_DIR/ecdsa.key || openssl ecparam -name prime256v1 -genkey -noout -out $ECDSA_DIR/ecdsa.key
    test -f $ECDSA_DIR/ecdsa.pub || openssl ec -in $ECDSA_DIR/ecdsa.key -pubout -out $ECDSA_DIR/ecdsa.pub

    test -f $ECDSA_DIR/encrypted.ecdsa.key || openssl ec -in $ECDSA_DIR/ecdsa.key -out $ECDSA_DIR/encrypted.ecdsa.key -aes256 -passout pass:$KEY_TEST_PW
    test -f $ECDSA_DIR/encrypted.ecdsa.pub || openssl ec -passin pass:$KEY_TEST_PW -in $ECDSA_DIR/encrypted.ecdsa.key -pubout -out $ECDSA_DIR/encrypted.ecdsa.pub

    test -f $ECDSA_DIR/ecdsa.crt || openssl req -new -x509 -key $ECDSA_DIR/ecdsa.key -days 825 -out $ECDSA_DIR/ecdsa.crt \
        -subj "/CN=example.com/O=Example Org" \
        -addext "subjectAltName=DNS:example.com,DNS:alt.example.com,IP:10.0.0.5"

    # ED25519_DIR=$CAROOT/ed25519_cert
    test -d $ED25519_DIR || mkdir $ED25519_DIR
    test -f $ED25519_DIR/ed25519.key || openssl genpkey -algorithm Ed25519 -out $ED25519_DIR/ed25519.key
    test -f $ED25519_DIR/ed25519.pub || openssl pkey -in $ED25519_DIR/ed25519.key -pubout -out $ED25519_DIR/ed25519.pub

    test -f $ED25519_DIR/encrypted.ed25519.key || openssl pkey -in $ED25519_DIR/ed25519.key -out $ED25519_DIR/encrypted.ed25519.key -aes256 -passout pass:$KEY_TEST_PW
    test -f $ED25519_DIR/encrypted.ed25519.pub || openssl pkey -passin pass:$KEY_TEST_PW -in $ED25519_DIR/encrypted.ed25519.key -pubout -out $ED25519_DIR/encrypted.ed25519.pub

    test -f $ED25519_DIR/ed25519.crt || openssl req -new -x509 -key $ED25519_DIR/ed25519.key -days 365 -out $ED25519_DIR/ed25519.crt \
    -subj "/CN=example.com/O=Example Org" -addext "subjectAltName=DNS:example.com,IP:127.0.0.1"

    # MLDSA_DIR=$CAROOT/mldsa-cert
    test -d $MLDSA_DIR || mkdir $MLDSA_DIR
    test -f $MLDSA_DIR/mldsa.key || openssl genpkey -algorithm ML-DSA-65 -out $MLDSA_DIR/mldsa.key
    test -f $MLDSA_DIR/mldsa.pub || openssl pkey -in $MLDSA_DIR/mldsa.key -pubout -out $MLDSA_DIR/mldsa.pub

    test -f $MLDSA_DIR/encrypted.mldsa.key || openssl pkey -in $MLDSA_DIR/mldsa.key -out $MLDSA_DIR/encrypted.mldsa.key -aes256 -passout pass:$KEY_TEST_PW
    test -f $MLDSA_DIR/encrypted.mldsa.pub || openssl pkey -passin pass:$KEY_TEST_PW -in $MLDSA_DIR/encrypted.mldsa.key -pubout -out $MLDSA_DIR/encrypted.mldsa.pub

    test -f $MLDSA_DIR/mldsa.crt || openssl req -new -x509 -key $MLDSA_DIR/mldsa.key -days 365 -out $MLDSA_DIR/mldsa.crt \
        -subj "/CN=example.com/O=Example Org" \
        -addext "subjectAltName=DNS:example.com,DNS:localhost,IP:127.0.0.1"
  '';

  scripts.test-curl.exec = ''
    curl "https://localhost:9443/get" -k -v
  '';

  scripts.certinfo-pq-vhost = {
    description = "Connect to the local ML-DSA nginx vhost (:9447) and print cert + TLS info";
    exec = ''
      gum format "## PQ vhost TLS (localhost:9447, ML-DSA-65)"
      ./dist/https-wrench certinfo \
        --tls-endpoint localhost:9447 \
        --tls-servername example.com \
        --ca-bundle "$MLDSA_DIR/mldsa.crt" \
        --tls-info
    '';
  };

  scripts.test-cmd-root-version.exec = ''
    gum format "## Command root --version"
    ./dist/https-wrench --version  2>&1 | grep -E '[0-9]\.+'
  '';

  scripts.test-cmd-requests-version.exec = ''
    gum format "## Command requests --version"
    ./dist/https-wrench requests --version 2>&1 | grep -E '[0-9]\.+'
  '';

  scripts.test-cmd-certinfo-version.exec = ''
    gum format "## Command certinfo --version"
    ./dist/https-wrench certinfo --version  2>&1 | grep -E '[0-9]\.+'
  '';

  scripts.test-cmd-root-help-when-no-flags.exec = ''
    gum format "## Command root, help when no flags"
    ./dist/https-wrench | grep "help for https-wrench"
  '';

  scripts.test-cmd-requests-help-when-no-flags.exec = ''
    gum format "## Command requests, help when no flags"
    ./dist/https-wrench requests | grep "help for requests"
  '';

  scripts.test-cmd-certinfo-help-when-no-flags.exec = ''
    gum format "## Command certinfo, help when no flags"
    ./dist/https-wrench certinfo | grep "help for certinfo"
  '';

  scripts.test-requests-show-sample-config.exec = ''
    gum format "## test request show sample config"
    ./dist/https-wrench requests --show-sample-config| grep 'requests:'
  '';

  scripts.test-requests-sample-config.exec = ''
    gum format "## test request with sample config"
    ./dist/https-wrench requests --config ./internal/cmd/embedded/config-example.yaml
  '';

  scripts.test-requests-k3s.exec = ''
    gum format "## test request against local k3s"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/https-wrench-k3s.yaml
  '';

  scripts.test-requests-methods.exec = ''
    gum format "## test request methods"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/http-methods.yaml
  '';

  scripts.test-requests-timeout.exec = ''
    gum format "## test request timeout"
    time ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/https-wrench-request-timeout.yaml | grep "Client.Timeout exceeded while awaiting headers"
  '';

  scripts.test-requests-unknown-ca.exec = ''
    gum format "## test request with unknown CA"

    set +o pipefail
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/unknown-ca.yaml | grep 'failed to verify certificate: x509: certificate signed by unknown authority'
  '';

  scripts.test-requests-insecure.exec = ''
    gum format "## test request insecure skip verify"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/insecure.yaml | grep 'StatusCode: 200'
  '';

  scripts.test-requests-syntax-highlight.exec = ''
    gum format "## test request body syntax highlight"
    ./dist/https-wrench requests --config  ./${config.env.EXAMPLES}/tests-configs/body-syntax-highlight.yaml --ca-bundle $CAROOT/rootCA.pem
  '';

  scripts.test-requests-body-regexp-match.exec = ''
    gum format "## test request body regexp match"
    ./dist/https-wrench requests --config  ./${config.env.EXAMPLES}/tests-configs/body-regexp-match.yaml  --ca-bundle $CAROOT/rootCA.pem | grep 'BodyRegexpMatch: true'
  '';

  scripts.test-requests-ca-bundle-file-success.exec = ''
    gum format "## test request with CA bundle file"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/ca-bundle-200.yaml --ca-bundle $CAROOT/rootCA.pem | grep "StatusCode: 200"
  '';

  scripts.test-requests-valid-cert-wrong-ca-bundle.exec = ''
    gum format "## test request with valid cert and wrong CA bundle file"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/repo-os76.yaml --ca-bundle $CAROOT/rootCA.pem 2>&1 | grep 'certificate signed by unknown authority'
  '';

  scripts.test-requests-ca-bundle-file-wrong-servername.exec = ''
    gum format "## test request with CA bundle file and wrong host name / servername"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/ca-bundle-wrong-servername.yaml --ca-bundle $CAROOT/rootCA.pem | grep 'tls: failed to verify certificate: x509'
  '';

  scripts.test-requests-proxy-protocol-ipv4.exec = ''
    gum format "## test request proxy protocol IPv4"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/proxy-protocol-ipv4.yaml --ca-bundle $CAROOT/rootCA.pem | grep '192.0.2.1'
  '';

  scripts.test-requests-proxy-protocol-ipv6.exec = ''
    gum format "## test request proxy protocol IPv6"
    ./dist/https-wrench requests --config ./${config.env.EXAMPLES}/tests-configs/proxy-protocol-ipv6.yaml --ca-bundle $CAROOT/rootCA.pem | grep '2001:db8::1'
  '';

  scripts.test-requests-ca-bundle-yaml.exec = ''
    gum format "## test request with CA bundle in YAML"

    CA_BUNDLE_YAML_TEST_FILE=./tests/https-wrench-tests-ca-bundle-string.yaml

    cat ./${config.env.EXAMPLES}/tests-configs/unknown-ca.yaml > $CA_BUNDLE_YAML_TEST_FILE

    echo "caBundle: |" >> $CA_BUNDLE_YAML_TEST_FILE
    while IFS= read -r line; do echo  "  $line" >> $CA_BUNDLE_YAML_TEST_FILE ; done < $CAROOT/rootCA.pem

    ./dist/https-wrench requests --config $CA_BUNDLE_YAML_TEST_FILE | grep 'StatusCode: 200'
  '';

  scripts.test-certinfo-encrypted-rsa-key.exec = ''
    gum format "## test certinfo load encrypted RSA key using env var"
    export CERTINFO_PKEY_PW=$KEY_TEST_PW
    set +o pipefail
    ./dist/https-wrench certinfo --key-file $CAROOT/encrypted.rsa.key | grep 'RSA'
  '';

  scripts.test-certinfo-encrypted-ecdsa-key.exec = ''
    gum format "## test certinfo load encrypted ECDSA key using env var"
    export CERTINFO_PKEY_PW=$KEY_TEST_PW
    set +o pipefail
    ./dist/https-wrench certinfo --key-file $ECDSA_DIR/encrypted.ecdsa.key | grep 'ECDSA'
  '';

  scripts.test-certinfo-encrypted-ed25519-key.exec = ''
    gum format "## test certinfo load encrypted ED25519 key using env var"
    export CERTINFO_PKEY_PW=$KEY_TEST_PW
    set +o pipefail
    ./dist/https-wrench certinfo --key-file $ED25519_DIR/encrypted.ed25519.key | grep 'Ed25519'
  '';

  scripts.test-certinfo-encrypted-key-cleanup-env.exec = ''
    unset CERTINFO_PKEY_PW
  '';

  scripts.test-certinfo-encrypted-rsa-key-expect = {
    exec = ''
      send -- "test certinfo load encrypted RSA key\n"
      spawn ./dist/https-wrench certinfo --key-file ${config.env.CAROOT}/encrypted.rsa.key
      expect "Private key is encrypted, please enter passphrase:"
      send -- "${config.env.KEY_TEST_PW}\r"
      expect "RSA"
      send -- "Key decrypted successfully\r"
      expect eof
    '';
    package = pkgs.expect;
  };

  scripts.test-certinfo-encrypted-ecdsa-key-expect = {
    exec = ''
      send -- "test certinfo load encrypted ECDSA key\n"
      spawn ./dist/https-wrench certinfo --key-file ${config.env.ECDSA_DIR}/encrypted.ecdsa.key
      expect "Private key is encrypted, please enter passphrase:"
      send -- "${config.env.KEY_TEST_PW}\r"
      expect "ECDSA"
      send -- "Key decrypted successfully\r"
      expect eof
    '';
    package = pkgs.expect;
  };

  scripts.test-certinfo-encrypted-ed25519-key-expect = {
    exec = ''
      send -- "test certinfo load encrypted ED25519 key\n"
      spawn ./dist/https-wrench certinfo --key-file ${config.env.ED25519_DIR}/encrypted.ed25519.key
      expect "Private key is encrypted, please enter passphrase:"
      send -- "${config.env.KEY_TEST_PW}\r"
      expect "Ed25519"
      send -- "Key decrypted successfully\r"
      expect eof
    '';
    package = pkgs.expect;
  };

  scripts.test-certinfo-pkcs1-rsa-key.exec = ''
    gum format "## test certinfo load PKCS1 RSA key"
    ./dist/https-wrench certinfo --key-file $CAROOT/rsa-private_traditional.key | grep -E 'Type\s+RSA'
  '';

  scripts.test-certinfo-pkcs1-ec-key.exec = ''
    gum format "## test certinfo load PKCS1 EC key"
    ./dist/https-wrench certinfo --key-file $CAROOT/private.ec.key | grep -E 'Type\s+ECDSA'
  '';

  scripts.test-certinfo-pkcs8-rsa-key.exec = ''
    gum format "## test certinfo load PKCS8 RSA key"
    ./dist/https-wrench certinfo --key-file $CAROOT/key.pem | grep -E 'Type\s+RSA'
  '';

  scripts.test-certinfo-pkcs8-ecdsa-key.exec = ''
    gum format "## test certinfo load PKCS8 ECDSA key"
    ./dist/https-wrench certinfo --key-file $ECDSA_DIR/ecdsa.key | grep -E 'Type\s+ECDSA'
  '';

  scripts.test-certinfo-pkcs8-ed25519-key.exec = ''
    gum format "## test certinfo load PKCS8 ED25519 key"
    ./dist/https-wrench certinfo --key-file $ED25519_DIR/ed25519.key | grep -E 'Type\s+Ed25519'
  '';

  scripts.test-certinfo-rsa-cert.exec = ''
    gum format "## test certinfo load RSA cert"
    ./dist/https-wrench certinfo --cert-bundle $CAROOT/cert.pem | grep -E 'PublicKeyAlgorithm\s+RSA'
  '';

  scripts.test-certinfo-ed25519-cert.exec = ''
    gum format "## test certinfo load ED25519 cert"
    ./dist/https-wrench certinfo --cert-bundle $ED25519_DIR/ed25519.crt | grep -E 'PublicKeyAlgorithm\s+Ed25519'
  '';

  scripts.test-certinfo-ecdsa-cert.exec = ''
    gum format "## test certinfo load ECDSA cert"
    ./dist/https-wrench certinfo --cert-bundle $ECDSA_DIR/ecdsa.crt | grep -E 'PublicKeyAlgorithm\s+ECDSA'
  '';

  scripts.test-certinfo-pkcs8-rsa-key-cert.exec = ''
    gum format "## test certinfo: PKCS8 RSA key + cert "
    ./dist/https-wrench certinfo --key-file $CAROOT/key.pem --cert-bundle $CAROOT/cert.pem | grep 'PrivateKey match: true'
  '';

  scripts.test-certinfo-pkcs8-ecdsa-key-cert.exec = ''
    gum format "## test certinfo: PKCS8 ECDSA key + cert"
    ./dist/https-wrench certinfo --key-file $ECDSA_DIR/ecdsa.key --cert-bundle $CAROOT/ecdsa.crt | grep 'PrivateKey match: true'
  '';

  scripts.test-certinfo-pkcs8-ed25519-key-cert.exec = ''
    gum format "## test certinfo: PKCS8 ED25519 key + cert"
    ./dist/https-wrench certinfo --key-file $ED25519_DIR/ed25519.key --cert-bundle $CAROOT/ed25519.crt | grep 'PrivateKey match: true'
  '';

  scripts.test-certinfo-tlsendpoint.exec = ''
    gum format "## test certinfo tlsEndpoint"
    ./dist/https-wrench certinfo --tls-endpoint repo.os76.xyz:443
  '';

  scripts.test-certinfo-tlsendpoint-wrong-ca-file.exec = ''
    gum format "## test certinfo tlsEndpoint with wrong CA file"
    set +o pipefail
    ./dist/https-wrench certinfo --tls-endpoint repo.os76.xyz:443 --ca-bundle $CAROOT/rootCA.pem 2>&1 | grep 'certificate signed by unknown authority'
  '';

  scripts.test-certinfo-tlsendpoint-servername.exec = ''
    gum format "## test certinfo tlsEndpoint servername"
    ./dist/https-wrench certinfo --tls-endpoint repo.os76.xyz:443 --tls-servername www.os76.xyz
  '';

  scripts.test-certinfo-tlsendpoint-timeout.exec = ''
    gum format "## test certinfo tlsEndpoint timeout"
    set +o pipefail
    ./dist/https-wrench certinfo --tls-endpoint repo.os76.xyz:344 2>&1 | grep timeout
  '';

  scripts.test-certinfo-tlsendpoint-malformed.exec = ''
    gum format "## test certinfo tlsEndpoint malformed (missing port)"
    set +o pipefail
    ./dist/https-wrench certinfo --tls-endpoint repo.os76.xyz | grep 'missing port in address'
  '';

  scripts.test-certinfo-tlsendpoint-insecure.exec = ''
    gum format "## test certinfo tlsEndpoint Insecure"
    ./dist/https-wrench certinfo --tls-endpoint localhost:9443 --tls-insecure | grep 'certificate signed by unknown authority'
  '';

  scripts.test-certinfo-tlsendpoint-ca-bundle.exec = ''
    gum format "## test certinfo tlsEndpoint + ca-bundle"
    ./dist/https-wrench certinfo --tls-endpoint localhost:9443 --ca-bundle $CAROOT/rootCA.pem
  '';

  scripts.test-certinfo-tlsendpoint-ca-bundle-ipv4.exec = ''
    gum format "## test certinfo IPv4 tlsEndpoint + ca-bundle"
    ./dist/https-wrench certinfo --tls-endpoint 127.0.0.1:9443 --ca-bundle $CAROOT/rootCA.pem
  '';

  scripts.test-certinfo-tlsendpoint-ca-bundle-ipv6.exec = ''
    gum format "## test certinfo IPV6 tlsEndpoint + ca-bundle "
    ./dist/https-wrench certinfo --tls-endpoint [::1]:9443 --ca-bundle $CAROOT/rootCA.pem
  '';

  scripts.test-certinfo-tlsendpoint-rsa-key-cert.exec = ''
    gum format "## test certinfo tlsEndpoint: RSA key + cert"
    ./dist/https-wrench certinfo --tls-endpoint localhost:9443 --tls-insecure --tls-servername example.com --key-file $CAROOT/key.pem | grep 'PrivateKey match: true'
  '';

  scripts.test-certinfo-tlsendpoint-ecdsa-key-cert.exec = ''
    gum format "## test certinfo tlsEndpoint: ECDSA key + cert"
    ./dist/https-wrench certinfo --tls-endpoint localhost:9446 --tls-insecure --tls-servername example.com --key-file $ECDSA_DIR/ecdsa.key | grep 'PrivateKey match: true'
  '';

  scripts.test-certinfo-tlsendpoint-ed25519-key-cert.exec = ''
    gum format "## test certinfo tlsEndpoint: ED25519 key + cert"
    ./dist/https-wrench certinfo --tls-endpoint localhost:9445 --tls-insecure --tls-servername example.com --key-file $ED25519_DIR/ed25519.key | grep 'PrivateKey match: true'
  '';

  scripts.run-requests-tests.exec = ''
    gum format "## Requests tests"

    # test-requests-sample-config
    test-requests-show-sample-config
    #test-requests-k3s
    test-requests-methods
    test-requests-timeout
    test-requests-insecure
    test-requests-syntax-highlight
    test-requests-unknown-ca
    test-requests-ca-bundle-file-success
    test-requests-ca-bundle-file-wrong-servername
    test-requests-valid-cert-wrong-ca-bundle
    test-requests-proxy-protocol-ipv4
    test-requests-proxy-protocol-ipv6
    test-requests-ca-bundle-yaml
    test-requests-body-regexp-match
  '';

  scripts.run-certinfo-tlsendpoint-tests.exec = ''
    gum format "## Certinfo tls-endpoint tests"

    test-certinfo-tlsendpoint
    test-certinfo-tlsendpoint-wrong-ca-file
    test-certinfo-tlsendpoint-servername
    test-certinfo-tlsendpoint-timeout
    test-certinfo-tlsendpoint-malformed
    test-certinfo-tlsendpoint-insecure
    test-certinfo-tlsendpoint-ca-bundle
    test-certinfo-tlsendpoint-ca-bundle-ipv4
    test-certinfo-tlsendpoint-ca-bundle-ipv6
    test-certinfo-tlsendpoint-rsa-key-cert
    test-certinfo-tlsendpoint-ecdsa-key-cert
    test-certinfo-tlsendpoint-ed25519-key-cert
  '';

  scripts.run-certinfo-priv-key-tests.exec = ''
    gum format "## Certinfo private key tests"

    test-certinfo-encrypted-rsa-key
    test-certinfo-encrypted-ecdsa-key
    test-certinfo-encrypted-ed25519-key
    test-certinfo-encrypted-key-cleanup-env
    test-certinfo-encrypted-rsa-key-expect
    test-certinfo-encrypted-ecdsa-key-expect
    test-certinfo-encrypted-ed25519-key-expect
    test-certinfo-pkcs1-ec-key
    test-certinfo-pkcs1-rsa-key
    test-certinfo-pkcs8-rsa-key
    test-certinfo-pkcs1-ec-key
    test-certinfo-pkcs8-ecdsa-key
  '';

  scripts.run-certinfo-cert-tests.exec = ''
    gum format "## Certinfo certificate tests"

    test-certinfo-rsa-cert
    test-certinfo-ed25519-cert
    test-certinfo-ecdsa-cert
  '';

  scripts.run-jwtinfo-test-auth0.exec = ''
    gum format "### JwtInfo request against Auth0"

    REQ_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/oauth/token"
    VALIDATION_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/.well-known/jwks.json"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-json "$JWTINFO_TEST_AUTH0" --validation-url "$VALIDATION_URL"
  '';

  scripts.run-jwtinfo-test-auth0-wrong-validation-url.exec = ''
    gum format "### JwtInfo request against Auth0 with wrong validation URL"

    REQ_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/oauth/token"
    VALIDATION_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/certs"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-json "$JWTINFO_TEST_AUTH0" --validation-url "$VALIDATION_URL"
  '';

  scripts.run-jwtinfo-test-auth0-no-validation.exec = ''
    gum format "### JwtInfo request against Auth0: no validation"

    REQ_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/oauth/token"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-json "$JWTINFO_TEST_AUTH0"
  '';

  scripts.run-jwtinfo-test-auth0-values-file.exec = ''
    gum format "### JwtInfo request against Auth0 with values file"

    REQ_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/oauth/token"
    VALIDATION_URL="https://dev-x3cci6dykofnlj5z.eu.auth0.com/.well-known/jwks.json"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-file  ~/.config/https-wrench/jwtinfo_test_auth0_req_values.json --validation-url "$VALIDATION_URL"
  '';

  scripts.run-jwtinfo-test-keycloak.exec = ''
    gum format "### JwtInfo request against priv Keycloak"

    REQ_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/token"
    VALIDATION_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/certs"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-json "$JWTINFO_TEST_KEYCLOAK" --validation-url "$VALIDATION_URL"
  '';

  scripts.run-jwtinfo-test-keycloak-values-file.exec = ''
    gum format "### JwtInfo request against priv Keycloak with values file"

    REQ_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/token"
    VALIDATION_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/certs"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" --request-values-file ~/.config/https-wrench/jwtinfo_test_keycloak_req_values.json --validation-url "$VALIDATION_URL"
  '';

  scripts.run-jwtinfo-test-keycloak-mixed-value-flags.exec = ''
    gum format "### JwtInfo request against priv Keycloak with mixed values flags"

    REQ_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/token"
    VALIDATION_URL="https://keycloak.k3s.os76.xyz/realms/os76/protocol/openid-connect/certs"

    ./dist/https-wrench jwtinfo --request-url "$REQ_URL" \
      --request-values client_id=istio-test-01 \
      --request-values-file ~/.config/https-wrench/jwtinfo_test_keycloak_req_values_pw_only.json \
      --request-values username=xeno \
      --request-values scope=openid \
      --request-values grant_type=password \
      --validation-url "$VALIDATION_URL"
  '';

  scripts.run-go-tests.exec = ''
    gum format "## Run GO tests"

    time gotest ./... -cover -coverprofile=cover.out
  '';

  scripts.run-go-tests-verbose.exec = ''
    gum format "## Run GO tests"

    time gotest -v ./... -cover -coverprofile=cover.out
  '';

  scripts.run-go-cover-html.exec = ''
    gum format "## Run GO cover HTML"

    go tool cover -html=cover.out
  '';

  scripts.run-go-cover-text.exec = ''
    gum format "## Run GO cover text"

    go tool cover -func=cover.out
  '';

  scripts.run-golangcilint-fix.exec = ''
    gum format "## Run golangci-lint"

    golangci-lint run --fix
  '';

  # BenchmarkProbeCiphersConcurrently — pprof / trace helpers
  #
  # Wraps the hermetic cipher-scan bench (I/O-bound localhost TLS, 10-worker pool).
  # One script per profile kind: combining -cpuprofile + -memprofile + -blockprofile
  # in a single go test run skews the results.
  #
  # Shared flags: -run '^$' (skip unit tests), -bench BenchmarkProbeCiphersConcurrently.
  # pprof / trace HTTP UI: 127.0.0.1:3111 (not 3000). Go 1.27 -http=:port is localhost-only.
  # Artifacts live under /tmp (*.out). Profiling can also leave internal/certinfo/certinfo.test;
  # each script registers an EXIT trap to remove both on any exit (test failure, Ctrl+C, normal). Do not commit them.
  # Mutex is last and likely quiet (the pool itself has no mutexes).

  scripts.BenchmarkProbeCiphersConcurrently_bench.exec = ''
    set -e
    gum format "## BenchmarkProbeCiphersConcurrently baseline (-count=6)"

    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchmem -count=6
  '';

  scripts.BenchmarkProbeCiphersConcurrently_cpu.exec = ''
    set -e
    trap 'rm -f /tmp/BenchmarkProbeCiphersConcurrently.cpu.out internal/certinfo/certinfo.test' EXIT
    gum format "## BenchmarkProbeCiphersConcurrently CPU profile (pprof :3111)"

    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchtime 2s -benchmem \
      -cpuprofile BenchmarkProbeCiphersConcurrently.cpu.out \
      -outputdir /tmp
    go tool pprof -http=:3111 /tmp/BenchmarkProbeCiphersConcurrently.cpu.out
  '';

  scripts.BenchmarkProbeCiphersConcurrently_mem.exec = ''
    set -e
    trap 'rm -f /tmp/BenchmarkProbeCiphersConcurrently.mem.out internal/certinfo/certinfo.test' EXIT
    gum format "## BenchmarkProbeCiphersConcurrently heap profile (pprof :3111, -alloc_objects)"

    # -alloc_objects = allocation count (GC pressure). Swap to -alloc_space for bytes.
    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchtime 2s -benchmem \
      -memprofile BenchmarkProbeCiphersConcurrently.mem.out \
      -outputdir /tmp
    go tool pprof -http=:3111 -alloc_objects /tmp/BenchmarkProbeCiphersConcurrently.mem.out
  '';

  scripts.BenchmarkProbeCiphersConcurrently_block.exec = ''
    set -e
    trap 'rm -f /tmp/BenchmarkProbeCiphersConcurrently.block.out internal/certinfo/certinfo.test' EXIT
    gum format "## BenchmarkProbeCiphersConcurrently block profile (pprof :3111)"

    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchtime 2s \
      -blockprofile BenchmarkProbeCiphersConcurrently.block.out \
      -outputdir /tmp
    go tool pprof -http=:3111 /tmp/BenchmarkProbeCiphersConcurrently.block.out
  '';

  scripts.BenchmarkProbeCiphersConcurrently_mutex.exec = ''
    set -e
    trap 'rm -f /tmp/BenchmarkProbeCiphersConcurrently.mutex.out internal/certinfo/certinfo.test' EXIT
    gum format "## BenchmarkProbeCiphersConcurrently mutex profile (pprof :3111)"

    # Likely quiet: probeCiphersConcurrently uses WaitGroup/channels, not mutexes.
    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchtime 2s \
      -mutexprofile BenchmarkProbeCiphersConcurrently.mutex.out \
      -outputdir /tmp
    go tool pprof -http=:3111 /tmp/BenchmarkProbeCiphersConcurrently.mutex.out
  '';

  scripts.BenchmarkProbeCiphersConcurrently_trace.exec = ''
    set -e
    trap 'rm -f /tmp/BenchmarkProbeCiphersConcurrently.trace.out internal/certinfo/certinfo.test' EXIT
    gum format "## BenchmarkProbeCiphersConcurrently execution trace"

    go test ./internal/certinfo/ -run '^$' \
      -bench BenchmarkProbeCiphersConcurrently -benchtime 1s \
      -trace /tmp/BenchmarkProbeCiphersConcurrently.trace.out \
      -outputdir /tmp
    go tool trace -http=:3111 /tmp/BenchmarkProbeCiphersConcurrently.trace.out
  '';

  enterShell = ''
    echo "https-wrench devenv ready"
    go version
    create-certs
  '';

  enterTest = ''
    gum format "# Running tests"
    # update-go-deps
    build

    #run-go-tests

    test-cmd-root-version
    test-cmd-requests-version
    test-cmd-certinfo-version
    test-cmd-root-help-when-no-flags
    test-cmd-requests-help-when-no-flags
    test-cmd-certinfo-help-when-no-flags

    run-requests-tests
    run-certinfo-priv-key-tests
    run-certinfo-cert-tests
    run-certinfo-tlsendpoint-tests

    run-jwtinfo-test-auth0
    run-jwtinfo-test-auth0-no-validation
  '';
}
