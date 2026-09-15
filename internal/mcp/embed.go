package mcp

import "embed"

//go:generate cp ../../https-wrench.schema.json assets/schema.json
//go:generate cp ../cmd/embedded/config-example.yaml assets/sample-config.yaml
//go:generate cp ../../assets/examples/https-wrench-k3s.yaml assets/examples/
//go:generate cp ../../assets/examples/https-wrench-response-certificates-filter.yaml assets/examples/
//go:generate cp ../../assets/examples/https-wrench-proxyProtocolV2.yaml assets/examples/
//go:generate cp ../../assets/examples/https-wrench-mcp-main-config.yaml assets/examples/

//go:embed assets/schema.json
//go:embed assets/sample-config.yaml
//go:embed assets/examples/*
var assets embed.FS

const (
	uriSchema       = "https-wrench://schema"
	uriMainConfig   = "https-wrench://main-config"
	uriSampleConfig = "https-wrench://sample-config"
	uriDocsRequests = "https-wrench://docs/requests"
	uriDocsCertinfo = "https-wrench://docs/certinfo"
	uriDocsJwtinfo  = "https-wrench://docs/jwtinfo"
	uriDocsJWKS     = "https-wrench://docs/jwks"
	uriExampleTmpl  = "https-wrench://examples/{name}"
)

var exampleFiles = map[string]string{
	"mcp-main-config":              "assets/examples/https-wrench-mcp-main-config.yaml",
	"k3s":                          "assets/examples/https-wrench-k3s.yaml",
	"response-certificates-filter": "assets/examples/https-wrench-response-certificates-filter.yaml",
	"proxy-protocol-v2":            "assets/examples/https-wrench-proxyProtocolV2.yaml",
}

const schemaCommentHeader = "# yaml-language-server: $schema=" + uriSchema

const requestsDocsMarkdown = `# https-wrench requests

Run probes with: ` + "`https-wrench requests --config path/to/file.yaml --format json`" + `

## Output formats

- ` + "`--format json`" + `: Machine-readable JSON output without ANSI styling.
- ` + "`--format text`" + `: Formatted terminal report with ANSI color styling.

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
- ` + uriMainConfig + `
- ` + uriSampleConfig + `
- ` + uriExampleTmpl + ` (names: mcp-main-config, k3s, response-certificates-filter, proxy-protocol-v2)
`

const certinfoDocsMarkdown = `# https-wrench certinfo

Inspect and verify x.509 certificates and keys from local files or remote TLS endpoints.

Run inspection with: ` + "`https-wrench certinfo [flags] --format json`" + `

## Output formats

- ` + "`--format json`" + `: Machine-readable JSON output without ANSI styling.
- ` + "`--format text`" + `: Formatted terminal report with lipgloss color styling.

## Common operations

- Remote TLS endpoint:
  ` + "`https-wrench certinfo --tls-endpoint example.com:443 --format json`" + `
- Local cert and key pairing:
  ` + "`https-wrench certinfo --cert-bundle cert.pem --key-file key.pem --format json`" + `
- Custom CA bundle verification:
  ` + "`https-wrench certinfo --cert-bundle cert.pem --ca-bundle ca.pem --format json`" + `
- TLS protocol and cipher suite probe:
  ` + "`https-wrench certinfo --tls-endpoint example.com:443 --tls-info --format json`" + `
`

const jwtinfoDocsMarkdown = `# https-wrench jwtinfo

Decode, inspect, and validate JSON Web Tokens (JWT).

Run inspection with: ` + "`https-wrench jwtinfo [flags] --format json`" + `

## Output formats

- ` + "`--format json`" + `: Machine-readable JSON output without ANSI styling.
- ` + "`--format text`" + `: Formatted terminal report with color styling.

## Common operations

- Inspect token from local file:
  ` + "`https-wrench jwtinfo --token-file path/to/token.jwt --format json`" + `
- Request token from OAuth endpoint:
  ` + "`https-wrench jwtinfo --request-url https://auth.example.com/oauth/token --format json`" + `
- Validate token signatures against remote JWKS:
  ` + "`https-wrench jwtinfo --token-file token.jwt " +
	`--validation-url https://auth.example.com/jwks.json --format json` + "`" + `
`

const jwksDocsMarkdown = `# https-wrench jwks

Generate JSON Web Key Sets (JWKS) from public keys for exposure on well-known endpoints.

Run generation with: ` + "`https-wrench jwks --public-key-file path/to/public.pem [flags] --format json`" + `

## Output formats

- ` + "`--format json`" + `: Machine-readable JSON output containing keys array without ANSI styling.
- ` + "`--format text`" + `: Formatted console view with banner and highlighted JSON.

## Common operations

- Generate public JWKS from RSA or ECDSA public key:
  ` + "`https-wrench jwks --public-key-file public.pem --format json`" + `
- Generate JWKS with custom Key ID (kid):
  ` + "`https-wrench jwks --public-key-file public.pem --kid my-key-id --format json`" + `
`
