package mcp

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerResources(server *sdkmcp.Server) {
	server.AddResource(&sdkmcp.Resource{
		URI:         uriSchema,
		Name:        "https-wrench JSON Schema",
		Description: "JSON Schema for requests configuration files",
		MIMEType:    "application/json",
	}, readStaticResource("assets/schema.json", uriSchema))

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

	server.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		URITemplate: uriExampleTmpl,
		Name:        "Example requests config",
		Description: "Example YAML configs from assets/examples " +
			"(names: k3s, response-certificates-filter, proxy-protocol-v2)",
		MIMEType: "text/yaml",
	}, readExampleResource)
}

func readStaticResource(assetPath, uri string) sdkmcp.ResourceHandler {
	return func(_ context.Context, _ *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		data, err := assets.ReadFile(assetPath)
		if err != nil {
			return nil, fmt.Errorf("read embedded asset %q: %w", assetPath, err)
		}

		return textResource(uri, string(data)), nil
	}
}

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

func textResource(uri, text string) *sdkmcp.ReadResourceResult {
	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:  uri,
			Text: text,
		}},
	}
}
