package cmd

import (
	"bytes"
	_ "embed"
	"testing"

	_ "github.com/breml/rootcerts"
	"github.com/stretchr/testify/require"
)

func TestRootCmd(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expected    []string
	}{
		{
			name:        "no args",
			args:        []string{},
			expectError: false,
			expected: []string{
				"HTTPS Wrench",
				"Usage:",
				"Available Commands:",
				"Flags:",
				"certinfo",
				"requests",
				"--config",
				"--version",
				"--help",
			},
		},

		{
			name:        "config flag not arg",
			args:        []string{"--config"},
			expectError: true,
			expected:    []string{"flag needs an argument: --config"},
		},
		{
			name:        "config flag valid arg",
			args:        []string{"--config", "./embedded/config-example.yaml"},
			expectError: false,
			// Unable to intercept the output
			expected: []string{},
		},
		{
			name:        "version",
			args:        []string{"--version"},
			expectError: false,
			expected:    []string{"development"},
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()

			if tt.expectError {
				require.Error(t, err)

				for _, expected := range tt.expected {
					require.ErrorContains(t, err, expected)
				}

				return
			}

			if !tt.expectError {
				require.NoError(t, err)
			}

			got := buf.String()

			for _, expected := range tt.expected {
				require.Contains(t, got, expected)
			}
		})
	}
}
