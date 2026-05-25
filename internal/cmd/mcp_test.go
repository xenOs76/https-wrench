package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsMCPCommand(t *testing.T) {
	// t.Parallel()
	//
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "mcp subcommand", args: []string{"https-wrench", "mcp"}, want: true},
		{name: "mcp with config flag", args: []string{"https-wrench", "--config", "x.yaml", "mcp"}, want: true},
		{name: "requests subcommand", args: []string{"https-wrench", "requests", "--config", "x.yaml"}, want: false},
		{name: "root help", args: []string{"https-wrench", "-h"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldArgs := os.Args

			t.Cleanup(func() { os.Args = oldArgs })

			os.Args = tt.args
			require.Equal(t, tt.want, isMCPCommand())
		})
	}
}
