<h1>HTTPS Wrench</h1>
<p align="center">
    <img width="450" alt="HTTPS Wrench Logo" src="./img/https-wrench-logo.jpg" /><br />
</p>
<p align="center">
    <i>HTTPS Wrench, a wrench not to bench</i>
</p>

**HTTPS Wrench** is a Golang CLI program to make HTTPS requests based on a YAML configuration file.   
**HTTPS Wrench** was born from the desire of a disposable Bash script to become a reliable tool for mechanics of the WWW.  
`https-wrench` will, one day, take the place of `curl` in the hearts and the eyes of whoever is about to migrate a DNS record from a webserver to a load balancer, reverse proxy, Ingress Gateway, Cloudfront distibution.   

## How to use

Check the help:

```bash
❯ https-wrench -h
A tool to make HTTPS requests based on a YAML configuration file

Usage:
  https-wrench [flags]
  https-wrench [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  requests    Make HTTPS requests

Flags:
      --config string        config file (default is $HOME/.https-wrench.yaml)
  -h, --help                 help for https-wrench
      --show-sample-config   Show a sample YAML configuration
      --version              Display the version

Use "https-wrench [command] --help" for more information about a command.
```

Generate a sample config file:
```bash
https-wrench --show-sample-config > sample-wrench.yaml
```

<details>
<summary>Sample configuration file</summary>

```yaml
---
debug: false
verbose: true
requests:
  - name: httpBunCom
    transportOverrideUrl: https://cat.httpbun.com:443
    userAgent: wrench-httpbun-ua

    requestHeaders:
      - key: x-custom-header
        value: custom-header-value
      - key: x-api-key
        value: api-value

    printResponseBody: true
    printResponseHeaders: true
    responseHeadersFilter:
      - X-Powered-By
      - Via
      - Content-Type

    hosts:
      - name: httpbun.com
        uriList:
          - /headers
          - /ip
          - /status/302
          - /status/404
          - /status/503
```
</details>


Make the HTTPS requests defined in the YAML file:
```bash
https-wrench --config sample-wrench.yaml requests
```

<details>
<summary>Output of the commands</summary>

The output should look like this:  

![HTTPS Wrench - sample output](./img/https-wrench-demo-sample-conf.gif "HTTPS Wrench - sample config output")

Or like this, if you customize one of the files in the ![examples](./examples/https-wrench-k3s.yaml) folder:  

![HTTPS Wrench - k3s output](./img/https-wrench-demo-k3s-example.gif "HTTPS Wrench - K3s requests output")

</details>

## How to install

### Manual download

Release binaries and DEB, RPM, APK packages can be downloaded from the [repo's releases section](https://github.com/xenOs76/https-wrench/releases).  
Binaries and packages are built for Linux and MacOS, `amd64` and `arm64`.   
No APT and YUM repositories yet, sorry.  

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

Nix users can use the following Nur repository to access `https-wrench`: [https://github.com/xenOs76/nur-packages](https://github.com/xenOs76/nur-packages).  
The repository is not listed yet in the general [Nix User Repository](https://github.com/nix-community/NUR) so the following methods can be used to install the package.  

Set a Nix channel: 
```bash
nix-channel --add https://github.com/xenos76/nur-packages/archive/main.tar.gz nur-os76
nix-channel --update
```

and add the package to a Nix shell:  
```bash
nix-shell -p '(import <nur-os76> { pkgs = import <nixpkgs> {}; }).https-wrench'
```

Or use a `flake.nix` like the following to achieve a similar result:  
```nix
{
  description = "Flake to fetch https-wrench from xenos76's NUR repo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nur-os76.url = "github:xenos76/nur-packages";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      nur-os76,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        https-wrench = pkgs.callPackage (nur-os76 + "/pkgs/https-wrench") { };
      in
      {
        packages.default = https-wrench;

        devShells.default = pkgs.mkShell {
          packages = [
            https-wrench
            pkgs.hello
          ];
        };
      }
    );
}
```

NixOS users could use a [flake like this](https://raw.githubusercontent.com/xenOs76/nixos-configs/refs/heads/main/flake.nix) to fetch the package.  
