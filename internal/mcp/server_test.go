package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	mcpserver "github.com/xenos76/https-wrench/internal/mcp"
)

func TestMCPServer_listsFeatures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	var toolNames []string

	for tool, err := range session.Tools(ctx, nil) {
		require.NoError(t, err)

		toolNames = append(toolNames, tool.Name)
	}

	require.ElementsMatch(t, []string{
		"validate_requests_config",
		"requests_config_template",
		"build_cli_command",
		"run_requests",
		"certinfo",
		"jwtinfo",
		"generate_jwks",
	}, toolNames)

	var resourceURIs []string

	for res, err := range session.Resources(ctx, nil) {
		require.NoError(t, err)

		resourceURIs = append(resourceURIs, res.URI)
	}

	require.Contains(t, resourceURIs, "https-wrench://schema")
	require.Contains(t, resourceURIs, "https-wrench://sample-config")
	require.Contains(t, resourceURIs, "https-wrench://docs/requests")

	var promptNames []string

	for prompt, err := range session.Prompts(ctx, nil) {
		require.NoError(t, err)

		promptNames = append(promptNames, prompt.Name)
	}

	require.Contains(t, promptNames, "author_requests_config")
}

func TestResources_readSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.ReadResource(ctx, &sdkmcp.ReadResourceParams{
		URI: "https-wrench://schema",
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Contents)
	require.Contains(t, res.Contents[0].Text, "HttpsWrenchConfiguration")
}

func TestResources_readExample(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.ReadResource(ctx, &sdkmcp.ReadResourceParams{
		URI: "https-wrench://examples/k3s",
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Contents)
	require.Contains(t, res.Contents[0].Text, "requests:")
}

func TestValidateRequestsConfig_emptyRequests(t *testing.T) {
	t.Parallel()

	out := callValidateTool(t, "verbose: true\nrequests: []\n")
	require.False(t, out["valid"].(bool))
	require.NotEmpty(t, out["errors"])
}

func TestValidateRequestsConfig_emptyHostName(t *testing.T) {
	t.Parallel()

	yaml := `verbose: true
requests:
  - name: example
    hosts:
      - name: ""
        uriList:
          - /
`

	out := callValidateTool(t, yaml)
	require.False(t, out["valid"].(bool))
	require.NotEmpty(t, out["errors"])
}

func TestRequestsConfigTemplate_missingHostname(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "requests_config_template",
		Arguments: map[string]any{},
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
}

func TestBuildCLICommand_quotedFlag(t *testing.T) {
	t.Parallel()

	out := callBuildCLITool(t, map[string]any{
		"command": "certinfo",
		"flags": map[string]any{
			"tls-endpoint": "host with spaces:443",
		},
	})
	require.Empty(t, out["errors"])
	require.Contains(t, out["command"], `"host with spaces:443"`)
}

func TestValidateRequestsConfig_valid(t *testing.T) {
	t.Parallel()

	yaml := `verbose: true
requests:
  - name: example
    requestMethod: HEAD
    hosts:
      - name: www.example.com
        uriList:
          - /
`

	out := callValidateTool(t, yaml)
	require.True(t, out["valid"].(bool))
	require.Empty(t, out["errors"])
}

func TestValidateRequestsConfig_missingVerbose(t *testing.T) {
	t.Parallel()

	yaml := `requests:
  - name: example
    hosts:
      - name: www.example.com
        uriList:
          - /
`

	out := callValidateTool(t, yaml)
	require.False(t, out["valid"].(bool))
	require.NotEmpty(t, out["errors"])
}

func TestValidateRequestsConfig_badURIList(t *testing.T) {
	t.Parallel()

	yaml := `verbose: true
requests:
  - name: example
    hosts:
      - name: www.example.com
        uriList:
          - no-leading-slash
`

	out := callValidateTool(t, yaml)
	require.False(t, out["valid"].(bool))
	require.NotEmpty(t, out["errors"])
}

func TestBuildCLICommand_certinfo(t *testing.T) {
	t.Parallel()

	out := callBuildCLITool(t, map[string]any{
		"command": "certinfo",
		"flags": map[string]any{
			"tls-endpoint": "example.com:443",
			"tls-info":     "true",
		},
	})

	require.Empty(t, out["errors"])
	require.Equal(t, "https-wrench certinfo --tls-endpoint example.com:443 --tls-info true", out["command"])
}

func TestBuildCLICommand_jwksMissingRequired(t *testing.T) {
	t.Parallel()

	out := callBuildCLITool(t, map[string]any{
		"command": "jwks",
		"flags":   map[string]any{},
	})

	require.NotEmpty(t, out["errors"])
	require.Empty(t, out["command"])
}

func TestRequestsConfigTemplate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "requests_config_template",
		Arguments: map[string]any{
			"hostname":             "www.example.com",
			"paths":                "/,/health",
			"transportOverrideUrl": "https://edge.example.net",
			"method":               "GET",
		},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	out := decodeStructuredOutput(t, res)
	yaml, ok := out["configYaml"].(string)
	require.True(t, ok)
	require.Contains(t, yaml, `transportOverrideUrl: "https://edge.example.net"`)
	require.Contains(t, yaml, "www.example.com")
	require.Contains(t, yaml, "/health")
}

func TestAuthorRequestsConfigPrompt(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.GetPrompt(ctx, &sdkmcp.GetPromptParams{
		Name: "author_requests_config",
		Arguments: map[string]string{
			"hostname": "app.example.com",
			"paths":    "/",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Messages)
	content, ok := res.Messages[0].Content.(*sdkmcp.TextContent)
	require.Truef(t, ok, "expected *sdkmcp.TextContent, got %T", res.Messages[0].Content)
	require.Contains(t, content.Text, "app.example.com")
	require.Contains(t, content.Text, "validate_requests_config")
}

func callValidateTool(t *testing.T, yaml string) map[string]any {
	t.Helper()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "validate_requests_config",
		Arguments: map[string]any{
			"configYaml": yaml,
		},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	return decodeStructuredOutput(t, res)
}

func callBuildCLITool(t *testing.T, args map[string]any) map[string]any {
	t.Helper()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "build_cli_command",
		Arguments: args,
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	return decodeStructuredOutput(t, res)
}

func decodeStructuredOutput(t *testing.T, res *sdkmcp.CallToolResult) map[string]any {
	t.Helper()

	require.NotNil(t, res.StructuredContent)

	data, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))

	return out
}
