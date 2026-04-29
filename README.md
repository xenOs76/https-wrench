# https-wrench

[![Test Coverage](https://raw.githubusercontent.com/xenOs76/https-wrench/badges/.badges/main/coverage.svg)](https://github.com/xenOs76/https-wrench/actions/workflows/codeChecks.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/xenos76/https-wrench)](https://goreportcard.com/report/github.com/xenos76/https-wrench)

<p align="center">
    <img width="450" alt="HTTPS Wrench Logo" src="./assets/img/https-wrench-logo.jpg"/><br />
    <i>HTTPS Wrench, a wrench not to bench</i>
</p>

**HTTPS Wrench** is a tool for maintainers of secure HTTP endpoints.  
It enables executing YAML-defined HTTPS requests, inspecting x.509 certificates, private keys, JSON Web Tokens (JWT), and
generating JSON Web Key Sets (JWKS).\
**HTTPS Wrench** was born from the desire of a disposable Bash script to become
a reliable companion for mechanics of the World Wide Web.\
`https-wrench` will, one day, take the place of `curl` in the hearts and the
eyes of whoever is about to migrate a DNS record from a webserver to a load
balancer, reverse proxy, Ingress Gateway, CloudFront distribution.

## How to use

Check the help:

<details>
<summary>View General Help (`https-wrench -h`)</summary>

```plain
❯ https-wrench -h

HTTPS Wrench is a tool for maintainers of secure HTTP endpoints. 
It enables executing YAML-defined HTTPS requests and performing in-depth 
inspection of x.509 certificates, private keys, and JSON Web Tokens.

https-wrench provides several specialized subcommands:

requests: Execute HTTPS requests according to a structured YAML configuration, 
supporting custom CA bundles and verbose output.

certinfo: Inspect PEM-encoded certificates and keys from local files or remote 
TLS endpoints. Verify certificate chains and key pairings.

jwtinfo: Decode, inspect, and validate JSON Web Tokens (JWT) using local files 
or remote JWKS endpoints.

jwks: Generate pretty-printed JSON Web Key Sets (JWKS) from public keys for 
exposure on well-known endpoints.

Distributed under an open-source license: https://github.com/xenOs76/https-wrench

Usage:
  https-wrench [flags]
  https-wrench [command]

Available Commands:
  certinfo    Inspect and verify x.509 certificates and keys
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  jwks        Generate a JSON Web Key Set (JWKS) from a public key
  jwtinfo     Inspect and validate JSON Web Tokens (JWT)
  requests    Execute YAML-defined HTTPS requests

Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
  -h, --help            help for https-wrench
      --version         Display the version

Use "https-wrench [command] --help" for more information about a command.
```

</details>

### HTTPS Wrench requests

Get the help:

<details>
<summary>View Requests Help (`https-wrench requests -h`)</summary>

```plain
❯ https-wrench requests -h

https-wrench requests is the subcommand that does HTTPS requests according to the configuration 
pointed by the --config flag.

A sample configuration can be generated as a starting point (--show-sample-config).

The Github repository has more configuration examples: 
https://github.com/xenOs76/https-wrench/tree/main/assets/examples

It also provides a JSON schema that can be used to validate new configuration files: 
https://github.com/xenOs76/https-wrench/blob/main/https-wrench.schema.json

Examples:
 https-wrench requests --show-sample-config > https-wrench-sample-config.yaml
 https-wrench requests --config https-wrench-sample-config.yaml

Usage:
  https-wrench requests [flags]

Flags:
      --ca-bundle string     Path to bundle file with CA certificates 
                             to use for validation
  -h, --help                 help for requests
      --show-sample-config   Show a sample YAML configuration

Global Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
      --version         Display the version
```

</details>

Generate a sample config file:

```shell
https-wrench requests --show-sample-config > https-wrench-sample-config.yaml
```

<details>
<summary>Sample configuration file</summary>

A comprehensive sample configuration file can be found in the repository at [`cmd/embedded/config-example.yaml`](./cmd/embedded/config-example.yaml).

</details>

Make the HTTPS requests defined in the YAML file:

```shell
https-wrench requests --config https-wrench-sample-config.yaml
```

### HTTPS Wrench certinfo

Get the help:

<details>
<summary>View Certinfo Help (`https-wrench certinfo -h`)</summary>

```plain
❯ https-wrench certinfo -h

Inspect and verify PEM encoded x.509 certificates and keys.

https-wrench certinfo can fetch certificates from a TLS endpoint, read from a PEM bundle file, and check if a 
private key matches any of the certificates.

The certificates can be verified against the system root CAs or a custom CA bundle file. 

The validation can be skipped.

If the private key is password protected, the password can be provided via the CERTINFO_PKEY_PW 
environment variable or will be prompted on stdin.

Examples:
  https-wrench certinfo --tls-endpoint example.com:443
  https-wrench certinfo --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --cert-bundle ./bundle.pem
  https-wrench certinfo --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --tls-servername www.example.com
  https-wrench certinfo --tls-endpoint [2001:db8::1]:443 --tls-insecure
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --tls-endpoint example.com:443
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --cert-bundle ./bundle.pem --key-file ./key.pem

Usage:
  https-wrench certinfo [flags]

Flags:
      --ca-bundle string        Path to bundle file with CA certificates 
                                to use for validation
      --cert-bundle string      Path to PEM Certificate bundle file
  -h, --help                    help for certinfo
      --key-file string         Path to PEM Key file
      --tls-endpoint string     TLS enabled endpoint exposing certificates to fetch. 
                                Forms: 'host:port', '[host]:port'. 
                                IPv6 addresses must be enclosed in square brackets, as in '[::1]:80'
      --tls-insecure            Skip certificate validation when connecting to a TLS endpoint
      --tls-servername string   ServerName to use when connecting to an SNI enabled TLS endpoint

Global Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
      --version         Display the version
```

</details>

Get info about a certificate and a key and see if their public keys match:

```shell
❯ https-wrench certinfo --cert-bundle rsa-pkcs8-crt.pem --key-file rsa-pkcs8-plaintext-private-key.pem
```

Get info about a certificate exposed by a remote TLS endpoint:

```shell
❯ https-wrench certinfo --tls-endpoint repo.os76.xyz:443
```

Get info about a self signed certificate exposed by a remote TLS endpoint,
validate it against a CA certificate and check if a specific privave key has
been used to generate the certificate:

```shell
❯ https-wrench certinfo --tls-endpoint localhost:9443 --ca-bundle rootCA.pem --key-file key.pem
```

### HTTPS Wrench jwtinfo

`jwtinfo` allows you to decode and inspect the claims of a JSON Web Token. It can also validate the token signature if a JWKS endpoint is provided.

<details>
<summary>View Jwtinfo Help (`https-wrench jwtinfo -h`)</summary>

```plain
❯ https-wrench jwtinfo -h

Inspect and validate JSON Web Tokens (JWT) from files or remote providers.

Examples:
  export REQ_URL="https://sample.provider/oauth/token"
  export REQ_VALUES="{\"login\":\"values\"}"
  export VALIDATION_URL="https://url.to/jkws.json"

  # Read a JWT token from a local file
  https-wrench jwtinfo --token-file /var/run/secrets/kubernetes.io/serviceaccount/token

  # Request a JWT token using inline values
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES

  # Request a JWT token using values file
  https-wrench jwtinfo --request-url $REQ_URL --request-values-file request-values.json

  # Request and validate a JWT token 
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES --validation-url $VALIDATION_URL

Usage:
  https-wrench jwtinfo [flags]

Flags:
  -h, --help                         help for jwtinfo
      --request-url string           HTTP address to use for the JWT token request
      --request-values-file string   File containing the JSON encoded values to use for the JWT token request
      --request-values-json string   JSON encoded values to use for the JWT token request
      --token-file string            File containing the JWT token
      --validation-url string        Url of the JSON Web Key Set (JWKS) to use for validating the JWT token

Global Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
      --version         Display the version
```

</details>

Decode a token from a file:

```shell
❯ https-wrench jwtinfo --token-file mytoken.jwt
```

### HTTPS Wrench jwks

`jwks` generates a public JSON Web Key Set from a PEM-encoded public key. This is useful for exposing your public keys at a `.well-known/jwks.json` endpoint.

<details>
<summary>View Jwks Help (`https-wrench jwks -h`)</summary>

```plain
❯ https-wrench jwks -h

Generate a pretty-printed JSON Web Key Set (JWKS) from a public key file.

The generated JWKS contains only public key parameters and is safe
to be exposed (e.g. at a /.well-known/jwks.json endpoint).

Examples:
  # Generate a public JWKS from an RSA public key
  https-wrench jwks --public-key-file rsa-public.pem

  # Generate a public JWKS with a custom Key ID (kid)
  https-wrench jwks --public-key-file ec-public.pem --kid "my-custom-key-id"

Usage:
  https-wrench jwks [flags]

Flags:
  -h, --help                     help for jwks
      --kid string               Optional explicit Key ID (kid) to use. If not provided, a thumbprint-based ID is inferred.
      --public-key-file string   File containing the PEM-encoded public key

Global Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
      --version         Display the version
```

</details>

Generate a JWKS with an inferred thumbprint KID:

```shell
❯ https-wrench jwks --public-key-file public.pem
```

### Sample output

<details>
<summary>HTTPS Wrench requests, sample configuration output</summary>
<img alt="HTTPS Wrench requests - sample config output" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_requests_sample-config.png">
</details>

<details>
<summary>HTTPS Wrench requests, sample requests against a K3s cluster</summary>
<img alt="HTTPS Wrench - k3s output" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_requests_k3s.png">
</details>

<details>
<summary>HTTPS Wrench certinfo, certificate and key</summary>
<img alt="HTTPS Wrench certinfo - certificate and key" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_certinfo_cert_and_key.png">
</details>

<details>
<summary>HTTPS Wrench certinfo, TLS Endpoint</summary>
<img alt="HTTPS Wrench certinfo - TLS Endpoint" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_certinfo_tls_endpoint.png">
</details>

<details>
<summary>HTTPS Wrench jwtinfo, request token</summary>
<img alt="HTTPS Wrench jwtingo - Request Token" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_jwtinfo_request_token.png">
</details>

<details>
<summary>HTTPS Wrench jwtinfo, read token and validate</summary>
<img alt="HTTPS Wrench jwtingo - Read Token" src="https://github.com/xenOs76/https-wrench/blob/main/assets/img/https-wrench_jwtinfo_read_validate_token.png">
</details>

## How to install

<details>
<summary>Go install</summary>

### Go install

HTTPS Wrench is "go gettable", so it can be installed with the following
command:

```shell
go install github.com/xenos76/https-wrench@latest
```

</details>
<details>
<summary>Manual download</summary>

### Manual download

Release binaries and DEB, RPM, APK packages can be downloaded from the
[repo's releases section](https://github.com/xenOs76/https-wrench/releases).\
Binaries and packages are built for Linux and MacOS, `amd64` and `arm64`.

</details>
<details>
<summary>APT</summary>

### APT

Configure the repo the following way:

```shell
echo "deb [trusted=yes] https://repo.os76.xyz/apt stable main" | sudo tee /etc/apt/sources.list.d/os76.list
```

then:

```shell
sudo apt-get update && sudo apt-get install -y https-wrench
```

</details>
<details>
<summary>YUM</summary>

### YUM

Configure the repo the following way:

```shell
echo '[os76]
name=OS76 Yum Repo
baseurl=https://repo.os76.xyz/yum/$basearch/
enabled=1
gpgcheck=0
repo_gpgcheck=0' | sudo tee /etc/yum.repos.d/os76.repo
```

then:

```shell
sudo yum install https-wrench
```

</details>
<details>
<summary>Docker image</summary>

### Docker image

Generate the config:

```shell
docker run --rm ghcr.io/xenos76/https-wrench:latest -h

docker run --rm ghcr.io/xenos76/https-wrench:latest --show-sample-config > sample-wrench.yaml
```

Run the `requests` command:

```shell
docker run  -v $(pwd)/sample-wrench.yaml:/https-wrench.yaml  --rm ghcr.io/xenos76/https-wrench:latest --config /https-wrench.yaml requests
```

</details>
<details>
<summary>Homebrew</summary>

### Homebrew

Add Os76 Homebrew repository:

```shell
brew tap xenos76/tap
```

Install `https-wrench`:

```shell
brew install --casks https-wrench
```

</details>
<details>
<summary>Nix/NUR</summary>

### Nix/NUR

Nix users can use the following Nur repository to access `https-wrench`:
[https://github.com/xenOs76/nur-packages](https://github.com/xenOs76/nur-packages).\
The repository is not listed yet in the general
[Nix User Repository](https://github.com/nix-community/NUR) so the following
methods can be used to install the package.

Set a Nix channel:

```shell
nix-channel --add https://github.com/xenos76/nur-packages/archive/main.tar.gz nur-os76
nix-channel --update
```

and add the package to a Nix shell:

```shell
nix-shell -p '(import <nur-os76> { pkgs = import <nixpkgs> {}; }).https-wrench'
```

Or use a `flake.nix` like the one from the
[nix-shell](/assets/examples/nix-shell) example to achieve a similar result:

```nix
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
```

NixOS users could use a
[flake like this](https://raw.githubusercontent.com/xenOs76/nixos-configs/refs/heads/main/flake.nix)
to fetch the package.

</details>
