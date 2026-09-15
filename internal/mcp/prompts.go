package mcp

import (
	"context"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerPrompts(server *sdkmcp.Server) {
	server.AddPrompt(&sdkmcp.Prompt{
		Name:        "author_requests_config",
		Description: "Guide for authoring a https-wrench requests YAML configuration",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "hostname", Description: "Application hostname (hosts[].name)", Required: true},
			{Name: "paths", Description: "Comma-separated URI paths starting with / (default /)"},
			{
				Name:        "transport_override_url",
				Description: "Optional https:// dial URL for transportOverrideUrl",
			},
			{Name: "insecure", Description: "Set to true to skip TLS verification for this request"},
			{Name: "method", Description: "HTTP method (default HEAD)"},
		},
	}, authorRequestsConfigPrompt)

	server.AddPrompt(&sdkmcp.Prompt{
		Name:        "inspect_certificate",
		Description: "Guide for inspecting x.509 certificates and TLS endpoints with https-wrench certinfo",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "tls_endpoint", Description: "Remote host:port (e.g. example.com:443)"},
			{Name: "cert_bundle", Description: "Path to PEM certificate bundle file"},
			{Name: "key_file", Description: "Path to PEM private key file to verify against certificates"},
			{Name: "ca_bundle", Description: "Optional path to custom CA bundle PEM file"},
			{Name: "tls_info", Description: "Set to true to probe TLS handshake cipher suite and protocol"},
		},
	}, inspectCertificatePrompt)

	server.AddPrompt(&sdkmcp.Prompt{
		Name:        "inspect_jwt",
		Description: "Guide for inspecting and validating JWT tokens with https-wrench jwtinfo",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "token_file", Description: "Path to file containing JWT token string"},
			{Name: "request_url", Description: "OAuth/OIDC token endpoint URL to fetch a token"},
			{Name: "validation_url", Description: "Remote JWKS URL to validate token signatures against"},
		},
	}, inspectJWTPrompt)

	server.AddPrompt(&sdkmcp.Prompt{
		Name:        "generate_jwks",
		Description: "Guide for generating a JSON Web Key Set from a public key with https-wrench jwks",
		Arguments: []*sdkmcp.PromptArgument{
			{Name: "public_key_file", Description: "Path to PEM-encoded public key file", Required: true},
			{Name: "kid", Description: "Optional key ID for the JWKS key entry"},
		},
	}, generateJWKSPrompt)
}

func authorRequestsConfigPrompt(_ context.Context, req *sdkmcp.GetPromptRequest) (*sdkmcp.GetPromptResult, error) {
	args := req.Params.Arguments
	input := requestsConfigTemplateInput{
		Hostname:             args["hostname"],
		Paths:                args["paths"],
		TransportOverrideURL: args["transport_override_url"],
		Method:               args["method"],
	}

	if strings.EqualFold(args["insecure"], "true") {
		input.Insecure = true
	}

	yaml, errs := buildRequestsConfigYAML(input)
	if len(errs) > 0 {
		return nil, &ValidationError{Messages: errs}
	}

	exampleHints := exampleResourceHints(input)
	text := strings.Join([]string{
		"Author a https-wrench requests configuration using the resources below.",
		"",
		"Reference resources:",
		"- " + uriSchema,
		"- " + uriMainConfig,
		"- " + uriSampleConfig,
		"- " + uriDocsRequests,
		exampleHints,
		"",
		"Starting skeleton YAML:",
		"```yaml",
		strings.TrimRight(yaml, "\n"),
		"```",
		"",
		"After editing, validate with the validate_requests_config tool.",
		"",
		"To run via CLI with machine-readable output:",
		"```shell",
		"https-wrench requests --config path/to/file.yaml --format json",
		"```",
	}, "\n")

	return &sdkmcp.GetPromptResult{
		Description: "Author a requests YAML config for https-wrench",
		Messages: []*sdkmcp.PromptMessage{{
			Role:    "user",
			Content: &sdkmcp.TextContent{Text: text},
		}},
	}, nil
}

func exampleResourceHints(input requestsConfigTemplateInput) string {
	var hints []string

	hints = append(hints, "- https-wrench://examples/mcp-main-config")

	if strings.TrimSpace(input.TransportOverrideURL) != "" {
		hints = append(hints, "- https-wrench://examples/k3s")
		hints = append(hints, "- https-wrench://examples/proxy-protocol-v2")
	}

	if input.Insecure {
		hints = append(hints, "- https-wrench://examples/k3s")
	}

	if len(hints) == 1 {
		hints = append(hints, "- https-wrench://examples/k3s")
	}

	return strings.Join(hints, "\n")
}

func inspectCertificatePrompt(
	_ context.Context,
	req *sdkmcp.GetPromptRequest,
) (*sdkmcp.GetPromptResult, error) {
	args := req.Params.Arguments
	tlsEndpoint := strings.TrimSpace(args["tls_endpoint"])
	certBundle := strings.TrimSpace(args["cert_bundle"])
	keyFile := strings.TrimSpace(args["key_file"])
	caBundle := strings.TrimSpace(args["ca_bundle"])
	tlsInfo := strings.EqualFold(args["tls_info"], "true")

	if tlsEndpoint == "" && certBundle == "" && keyFile == "" {
		tlsEndpoint = "example.com:443"
	}

	cmdParts := []string{"https-wrench certinfo"}

	if tlsEndpoint != "" {
		cmdParts = append(cmdParts, "--tls-endpoint", shellQuote(tlsEndpoint))
	}

	if certBundle != "" {
		cmdParts = append(cmdParts, "--cert-bundle", shellQuote(certBundle))
	}

	if keyFile != "" {
		cmdParts = append(cmdParts, "--key-file", shellQuote(keyFile))
	}

	if caBundle != "" {
		cmdParts = append(cmdParts, "--ca-bundle", shellQuote(caBundle))
	}

	if tlsInfo {
		cmdParts = append(cmdParts, "--tls-info")
	}

	cmdParts = append(cmdParts, "--format json")

	cmd := strings.Join(cmdParts, " ")

	text := strings.Join([]string{
		"Inspect x.509 certificates, keys, or TLS endpoints using the resources below.",
		"",
		"Reference resource:",
		"- " + uriDocsCertinfo,
		"",
		"Direct MCP execution:",
		"- Use the `certinfo` tool for in-process JSON inspection.",
		"",
		"Recommended CLI command (machine-readable output):",
		"```shell",
		cmd,
		"```",
	}, "\n")

	return &sdkmcp.GetPromptResult{
		Description: "Inspect certificates and TLS endpoints with https-wrench certinfo",
		Messages: []*sdkmcp.PromptMessage{{
			Role:    "user",
			Content: &sdkmcp.TextContent{Text: text},
		}},
	}, nil
}

func inspectJWTPrompt(
	_ context.Context,
	req *sdkmcp.GetPromptRequest,
) (*sdkmcp.GetPromptResult, error) {
	args := req.Params.Arguments
	tokenFile := strings.TrimSpace(args["token_file"])
	requestURL := strings.TrimSpace(args["request_url"])
	validationURL := strings.TrimSpace(args["validation_url"])

	cmdParts := []string{"https-wrench jwtinfo"}

	if tokenFile != "" {
		cmdParts = append(cmdParts, "--token-file", shellQuote(tokenFile))
	} else if requestURL != "" {
		cmdParts = append(cmdParts, "--request-url", shellQuote(requestURL))
	} else {
		cmdParts = append(cmdParts, "--token-file path/to/token.jwt")
	}

	if validationURL != "" {
		cmdParts = append(cmdParts, "--validation-url", shellQuote(validationURL))
	}

	cmdParts = append(cmdParts, "--format json")

	cmd := strings.Join(cmdParts, " ")

	text := strings.Join([]string{
		"Decode, inspect, and validate JSON Web Tokens using the resources below.",
		"",
		"Reference resource:",
		"- " + uriDocsJwtinfo,
		"",
		"Direct MCP execution:",
		"- Use the `jwtinfo` tool for in-process JSON inspection.",
		"",
		"Recommended CLI command (machine-readable output):",
		"```shell",
		cmd,
		"```",
	}, "\n")

	return &sdkmcp.GetPromptResult{
		Description: "Inspect and validate JWT tokens with https-wrench jwtinfo",
		Messages: []*sdkmcp.PromptMessage{{
			Role:    "user",
			Content: &sdkmcp.TextContent{Text: text},
		}},
	}, nil
}

func generateJWKSPrompt(
	_ context.Context,
	req *sdkmcp.GetPromptRequest,
) (*sdkmcp.GetPromptResult, error) {
	args := req.Params.Arguments
	publicKeyFile := strings.TrimSpace(args["public_key_file"])
	kid := strings.TrimSpace(args["kid"])

	if publicKeyFile == "" {
		publicKeyFile = "path/to/public.pem"
	}

	cmdParts := []string{"https-wrench jwks", "--public-key-file", shellQuote(publicKeyFile)}

	if kid != "" {
		cmdParts = append(cmdParts, "--kid", shellQuote(kid))
	}

	cmdParts = append(cmdParts, "--format json")

	cmd := strings.Join(cmdParts, " ")

	text := strings.Join([]string{
		"Generate a public JSON Web Key Set from a public key file using the resources below.",
		"",
		"Reference resource:",
		"- " + uriDocsJWKS,
		"",
		"Direct MCP execution:",
		"- Use the `generate_jwks` tool for in-process JSON JWKS generation.",
		"",
		"Recommended CLI command (machine-readable output):",
		"```shell",
		cmd,
		"```",
	}, "\n")

	return &sdkmcp.GetPromptResult{
		Description: "Generate a JWKS from a public key with https-wrench jwks",
		Messages: []*sdkmcp.PromptMessage{{
			Role:    "user",
			Content: &sdkmcp.TextContent{Text: text},
		}},
	}, nil
}
