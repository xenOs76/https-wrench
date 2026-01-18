<h1>HTTPS Wrench</h1>
<p align="center">
    <img width="450" alt="HTTPS Wrench Logo" src="./assets/img/https-wrench-logo.jpg"/><br />
</p>
<p align="center">
    <i>HTTPS Wrench, a wrench not to bench</i>
</p>
<p align="center">
    <a href="https://goreportcard.com/report/github.com/xenos76/https-wrench">
        <img alt="Go Report Card badge for HTTPS Wrench" src="https://goreportcard.com/badge/github.com/xenos76/https-wrench"/>
    </a>
    <a href="https://github.com/xenOs76/https-wrench/actions/workflows/codeChecks.yml">
        <img alt="Test Coverage" src="https://raw.githubusercontent.com/xenOs76/https-wrench/badges/.badges/main/coverage.svg"/>
    </a>
</p>

**HTTPS Wrench** is a CLI program to make Yaml defined HTTPS requests and to
inspect x.509 certificates and keys.\
**HTTPS Wrench** was born from the desire of a disposable Bash script to become
a reliable tool for mechanics of the World Wide Web.\
`https-wrench` will, one day, take the place of `curl` in the hearts and the
eyes of whoever is about to migrate a DNS record from a webserver to a load
balancer, reverse proxy, Ingress Gateway, CloudFront distribution.

## How to use

Check the help:

```
❯ https-wrench -h

HTTPS Wrench is a tool to make HTTPS requests according to a Yaml configuration file and to inspect x.509 certificates and keys.

https-wrench has two subcommands: requests and certinfo.

requests is the subcommand that does HTTPS requests according to the configuration provided
by the --config flag.

certinfo is a subcommand that reads information from PEM encoded x.509 certificates and keys. The certificates
can be read from local files or TLS enabled endpoints.

certinfo can compare public keys extracted from certificates and private keys to check if they match.

HTTPS Wrench is distributed with an open source license and available at the following address:
https://github.com/xenOs76/https-wrench

Usage:
  https-wrench [flags]
  https-wrench [command]

Available Commands:
  certinfo    Shows information about x.509 certificates and keys
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  requests    Make HTTPS requests defined in the YAML configuration file

Flags:
      --config string   config file (default is $HOME/.https-wrench.yaml)
  -h, --help            help for https-wrench
      --version         Display the version

Use "https-wrench [command] --help" for more information about a command.
```

### HTTPS Wrench requests

Get the help:

```
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

Generate a sample config file:

```bash
https-wrench requests --show-sample-config > https-wrench-sample-config.yaml
```

<details>
<summary>Sample configuration file</summary>

```yaml
---
debug: false
verbose: true
requests:
  - name: httpBunComGet

    transportOverrideUrl: https://cat.httpbun.com:443
    clientTimeout: 3

    requestDebug: false
    responseDebug: false

    printResponseBody: true
    printResponseHeaders: true

    userAgent: wrench-custom-ua

    requestHeaders:
      - key: x-custom-header
        value: custom-header-value
      - key: x-api-key
        value: api-value

    responseHeadersFilter:
      - X-Powered-By
      - Via
      - Content-Type

    hosts:
      - name: httpbun.com
        uriList:
          - /headers
          - /status/302
          - /status/404
          - /status/503

  - name: httpBunComCerts

    printResponseCertificates: true

    hosts:
      - name: httpbun.com
```

</details>

Make the HTTPS requests defined in the YAML file:

```bash
https-wrench requests --config https-wrench-sample-config.yaml
```

### HTTPS Wrench certinfo

Get the help:

```plain
❯ https-wrench certinfo -h

HTTPS Wrench certinfo: shows information about PEM certificates and keys.

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

### Sample output of the commands

<details>
<summary>HTTPS Wrench requests, (long) sample configuration output</summary>
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

## How to install

### Go install

HTTPS Wrench is "go gettable", so it can be installed with the following command
when having a proper `go` setup:

```bash
go install github.com/xenos76/https-wrench@latest
```

### Manual download

Release binaries and DEB, RPM, APK packages can be downloaded from the
[repo's releases section](https://github.com/xenOs76/https-wrench/releases).\
Binaries and packages are built for Linux and MacOS, `amd64` and `arm64`.

### APT

Configure the repo the following way:

```bash
echo "deb [trusted=yes] https://repo.os76.xyz/apt stable main" | sudo tee /etc/apt/sources.list.d/os76.list
```

then:

```bash
sudo apt-get update && sudo apt-get install -y https-wrench
```

### YUM

Configure the repo the following way:

```bash
echo '[os76]
name=OS76 Yum Repo
baseurl=https://repo.os76.xyz/yum/$basearch/
enabled=1
gpgcheck=0
repo_gpgcheck=0' | sudo tee /etc/yum.repos.d/os76.repo
```

then:

```bash
sudo yum install https-wrench
```

### Docker image

Generate the config:

```bash
docker run --rm ghcr.io/xenos76/https-wrench:latest -h

docker run --rm ghcr.io/xenos76/https-wrench:latest --show-sample-config > sample-wrench.yaml
```

Run the `requests` command:

```bash
docker run  -v $(pwd)/sample-wrench.yaml:/https-wrench.yaml  --rm ghcr.io/xenos76/https-wrench:latest --config /https-wrench.yaml requests
```

### Homebrew

Add Os76 Homebrew repository:

```bash
brew tap xenos76/tap
```

Install `https-wrench`:

```bash
brew install --casks https-wrench
```

### Nix/NUR

Nix users can use the following Nur repository to access `https-wrench`:
[https://github.com/xenOs76/nur-packages](https://github.com/xenOs76/nur-packages).\
The repository is not listed yet in the general
[Nix User Repository](https://github.com/nix-community/NUR) so the following
methods can be used to install the package.

Set a Nix channel:

```bash
nix-channel --add https://github.com/xenos76/nur-packages/archive/main.tar.gz nur-os76
nix-channel --update
```

and add the package to a Nix shell:

```bash
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
