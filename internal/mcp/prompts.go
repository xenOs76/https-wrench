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
			{Name: "transport_override_url", Description: "Optional https:// dial URL for transportOverrideUrl"},
			{Name: "insecure", Description: "Set to true to skip TLS verification for this request"},
			{Name: "method", Description: "HTTP method (default HEAD)"},
		},
	}, authorRequestsConfigPrompt)
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

	if strings.TrimSpace(input.TransportOverrideURL) != "" {
		hints = append(hints, "- https-wrench://examples/k3s")
		hints = append(hints, "- https-wrench://examples/proxy-protocol-v2")
	}

	if input.Insecure {
		hints = append(hints, "- https-wrench://examples/k3s")
	}

	if len(hints) == 0 {
		hints = append(hints, "- https-wrench://examples/k3s")
	}

	return strings.Join(hints, "\n")
}
