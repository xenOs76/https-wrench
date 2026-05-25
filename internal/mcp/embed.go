package mcp

import "embed"

//go:generate cp ../../https-wrench.schema.json assets/schema.json
//go:generate cp ../cmd/embedded/config-example.yaml assets/sample-config.yaml
//go:generate cp ../../assets/examples/https-wrench-k3s.yaml assets/examples/
//go:generate cp ../../assets/examples/https-wrench-response-certificates-filter.yaml assets/examples/
//go:generate cp ../../assets/examples/https-wrench-proxyProtocolV2.yaml assets/examples/

//go:embed assets/schema.json
//go:embed assets/sample-config.yaml
//go:embed assets/examples/*
var assets embed.FS

const (
	uriSchema       = "https-wrench://schema"
	uriSampleConfig = "https-wrench://sample-config"
	uriDocsRequests = "https-wrench://docs/requests"
	uriExampleTmpl  = "https-wrench://examples/{name}"
)

var exampleFiles = map[string]string{
	"k3s":                          "assets/examples/https-wrench-k3s.yaml",
	"response-certificates-filter": "assets/examples/https-wrench-response-certificates-filter.yaml",
	"proxy-protocol-v2":            "assets/examples/https-wrench-proxyProtocolV2.yaml",
}

const schemaCommentHeader = "# yaml-language-server: $schema=" +
	"https://raw.githubusercontent.com/xenOs76/https-wrench/refs/heads/main/https-wrench.schema.json"

const requestsDocsMarkdown = `# https-wrench requests

Run probes with: ` + "`https-wrench requests --config <file.yaml>`" + `

## Top level

| Field | Notes |
|-------|-------|
| ` + "`verbose`" + ` | Required boolean. |
| ` + "`debug`" + ` | Optional. |
| ` + "`caBundle`" + ` | Optional PEM CA bundle path or inline PEM. |
| ` + "`requests`" + ` | Required array of request objects. |

## Each request

**Required:** ` + "`name`" + `, ` + "`hosts`" + ` (non-empty).

- ` + "`hosts[].name`" + `: hostname for URL and SNI.
- ` + "`hosts[].uriList`" + `: paths must start with ` + "`/`" + `.
- ` + "`transportOverrideUrl`" + `: optional dial URL (` + "`https://...`" + `); ` +
	`logical host stays in ` + "`hosts[].name`" + `.
- ` + "`insecure`" + `: skip TLS verification when dial address does not match cert.
- ` + "`requestMethod`" + `: GET, HEAD, POST, etc.
- ` + "`printResponseBody`" + `, ` + "`printResponseHeaders`" + `, ` +
	"`printResponseCertificates`" + `: response inspection toggles.

## MCP resources

- ` + uriSchema + `
- ` + uriSampleConfig + `
- ` + uriExampleTmpl + ` (names: k3s, response-certificates-filter, proxy-protocol-v2)
`
