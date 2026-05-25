package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverInstructions = "MCP server for https-wrench. " +
	"Use resources and prompts to author requests YAML, validate configs, and build CLI commands. " +
	"Execution tools run requests probes, certinfo, jwtinfo, and JWKS generation directly."

// Run starts the https-wrench MCP server on stdin/stdout until the client disconnects.
func Run(ctx context.Context, version string) error {
	server := NewServer(version)

	return server.Run(ctx, &sdkmcp.StdioTransport{})
}

// NewServer builds an MCP server with assist and execution resources, prompts, and tools.
func NewServer(version string) *sdkmcp.Server {
	if version == "" {
		version = "development"
	}

	server := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "https-wrench",
		Version: version,
	}, &sdkmcp.ServerOptions{
		Instructions: serverInstructions,
	})

	registerResources(server)
	registerPrompts(server)
	registerTools(server)

	return server
}

// RunInMemory connects the server to an in-memory transport pair for tests.
func RunInMemory(ctx context.Context, version string) (*sdkmcp.ClientSession, func(), error) {
	server := NewServer(version)
	client := sdkmcp.NewClient(&sdkmcp.Implementation{
		Name:    "https-wrench-test-client",
		Version: "test",
	}, nil)

	t1, t2 := sdkmcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		return nil, nil, fmt.Errorf("connect server: %w", err)
	}

	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connect client: %w", err)
	}

	cleanup := func() {
		_ = session.Close()
	}

	return session, cleanup, nil
}
