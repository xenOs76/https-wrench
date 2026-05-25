/*
Copyright © 2026 Zeno Belli <xeno@os76.xyz>
*/

package cmd

import (
	"github.com/spf13/cobra"
	mcpserver "github.com/xenos76/https-wrench/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run an MCP server for AI agent integration",
	Long: `Start a Model Context Protocol server on stdin/stdout.

The server exposes reference resources (JSON schema, sample config, examples),
prompts for authoring requests YAML, and assist tools to validate configs and
build CLI invocations for other https-wrench subcommands.

Configure in Cursor or Claude Desktop:

  {
    "mcpServers": {
      "https-wrench": {
        "command": "https-wrench",
        "args": ["mcp"]
      }
    }
  }
`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return mcpserver.Run(cmd.Context(), version)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
