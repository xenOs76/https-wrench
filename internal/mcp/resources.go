package mcp

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerResources registers static assets, schemas, and markdown cheat sheets on the server.
func registerResources(server *sdkmcp.Server) {
	server.AddResource(&sdkmcp.Resource{
		URI:         uriSchema,
		Name:        "https-wrench JSON Schema",
		Description: "JSON Schema for requests configuration files",
		MIMEType:    "application/json",
	}, readStaticResource("assets/schema.json", uriSchema))

	server.AddResource(&sdkmcp.Resource{
		URI:         uriMainConfig,
		Name:        "Main requests configuration reference",
		Description: "Comprehensive main YAML configuration demonstrating all https-wrench options",
		MIMEType:    "text/yaml",
	}, readStaticResource("assets/examples/https-wrench-mcp-main-config.yaml", uriMainConfig))

	server.AddResource(&sdkmcp.Resource{
		URI:         uriSampleConfig,
		Name:        "Sample requests config",
		Description: "Starter YAML configuration for https-wrench requests",
		MIMEType:    "text/yaml",
	}, readStaticResource("assets/sample-config.yaml", uriSampleConfig))

	server.AddResource(&sdkmcp.Resource{
		URI:         uriDocsRequests,
		Name:        "requests command reference",
		Description: "Markdown cheat sheet for authoring requests YAML",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		return textResource(uriDocsRequests, requestsDocsMarkdown), nil
	})

	server.AddResource(&sdkmcp.Resource{
		URI:         uriDocsCertinfo,
		Name:        "certinfo command reference",
		Description: "Markdown cheat sheet for inspecting x.509 certs and TLS endpoints",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		return textResource(uriDocsCertinfo, certinfoDocsMarkdown), nil
	})

	server.AddResource(&sdkmcp.Resource{
		URI:         uriDocsJwtinfo,
		Name:        "jwtinfo command reference",
		Description: "Markdown cheat sheet for decoding and validating JWT tokens",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		return textResource(uriDocsJwtinfo, jwtinfoDocsMarkdown), nil
	})

	server.AddResource(&sdkmcp.Resource{
		URI:         uriDocsJWKS,
		Name:        "jwks command reference",
		Description: "Markdown cheat sheet for generating JWKS from public keys",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		return textResource(uriDocsJWKS, jwksDocsMarkdown), nil
	})

	server.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		URITemplate: uriExampleTmpl,
		Name:        "Example requests config",
		Description: "Example YAML configs from assets/examples " +
			"(names: mcp-main-config, k3s, response-certificates-filter, proxy-protocol-v2)",
		MIMEType: "text/yaml",
	}, readExampleResource)
}

// readStaticResource returns a resource reader closure for embedded assets.
func readStaticResource(assetPath, uri string) sdkmcp.ResourceHandler {
	return func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		data, err := assets.ReadFile(assetPath)
		if err != nil {
			return nil, fmt.Errorf("read embedded asset %q: %w", assetPath, err)
		}

		return textResource(uri, string(data)), nil
	}
}

// readExampleResource reads an example configuration template asset by name.
func readExampleResource(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	name := strings.TrimPrefix(req.Params.URI, "https-wrench://examples/")
	if name == req.Params.URI || name == "" {
		return nil, sdkmcp.ResourceNotFoundError(req.Params.URI)
	}

	assetPath, ok := exampleFiles[name]
	if !ok {
		return nil, sdkmcp.ResourceNotFoundError(req.Params.URI)
	}

	data, err := assets.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("read example %q: %w", name, err)
	}

	return textResource(req.Params.URI, string(data)), nil
}

// textResource wraps text content into an MCP ReadResourceResult.
func textResource(uri, text string) *sdkmcp.ReadResourceResult {
	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:  uri,
			Text: text,
		}},
	}
}
