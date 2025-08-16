<h1>HTTPS Wrench</h1>
<p align="center">
    <img width="450" alt="HTTPS Wrench Logo" src="./img/https-wrench-logo.jpg" /><br />
</p>
<p align="center">
    <i>HTTPS Wrench, a wrench not to bench</i>
</p>

**HTTPS Wrench** is a Golang CLI program to make HTTPS requests based on a YAML configuration file.   
**HTTPS Wrench** was born from a disposable Bash script's desire to become a reliable tool for WWW mechanics.  
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

Make the HTTPS requests defined in the YAML file:
```bash
https-wrench --config sample-wrench.yaml requests
```

The output should look like this:  

![HTTPS Wrench - sample output](./img/https-wrench-demo-sample-conf.gif "HTTPS Wrench - sample config output")

Or like this, if you customize one of the files in the ![examples](./examples/https-wrench-k3s.yaml) folder:  

![HTTPS Wrench - k3s output](./img/https-wrench-demo-k3s-example.gif "HTTPS Wrench - K3s requests output")


## How to install

**TBD**

### Release binaries
### DEB/RPM/APK 
### Docker image

```bash
docker run -v $(pwd)/examples/https-wrench-k3s.yaml:/https-wrench.yaml --rm https-wrench  --config /https-wrench.yaml requests
```

### Homebrew 
### Nix/Nur

