package cmd

import (
	"bytes"
	_ "embed"
	"testing"

	_ "github.com/breml/rootcerts"
	"github.com/stretchr/testify/require"
)

func TestRequestsCmd(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errMsgs     []string
		expected    []string
	}{
		{
			name:        "no args",
			args:        []string{"requests"},
			expectError: false,
			expected: []string{
				"https-wrench requests",
				"Usage:",
				"Flags:",
				"Global Flags:",
				"--config",
				"--ca-bundle",
				"--show-sample-config",
				"--version",
				"--help",
			},
		},
		{
			name:        "show sample config",
			args:        []string{"requests", "--show-sample-config"},
			expectError: false,
			expected: []string{
				"https-wrench.schema.json",
				"requests:",
				"transportOverrideUrl:",
				"requestHeaders:",
			},
		},

		{
			name:        "ca-bundle flag no value",
			args:        []string{"requests", "--ca-bundle"},
			expectError: true,
			errMsgs: []string{
				"flag needs an argument: --ca-bundle",
			},
			expected: []string{
				"https-wrench requests [flags]",
				"--ca-bundle string",
				"Usage:",
				"--version         Display the version",
			},
		},

		{
			name:        "config flag no file",
			args:        []string{"requests", "--config"},
			expectError: true,
			errMsgs: []string{
				"flag needs an argument: --config",
			},
			expected: []string{
				"https-wrench requests [flags]",
				"--ca-bundle string",
				"Usage:",
				"--version         Display the version",
			},
		},

		// WARN conflicts with same test for rootCmd
		// {
		// 	name: "config flag file not exist",
		// 	args: []string{
		// 		"requests",
		// 		"--config",
		// 		"/not-existent-file",
		// 	},
		// 	expectError: false,
		// 	expected: []string{
		// 		"Config file not found:",
		// 		"https-wrench requests [flags]",
		// 		"--ca-bundle string",
		// 		"Usage:",
		// 		"--version         Display the version",
		// 	},
		// },
		//
		// WARN conflicts with same test for rootCmd
		// {
		// 	name:        "version",
		// 	args:        []string{"requests", "--version"},
		// 	expectError: false,
		// 	expected: []string{
		// 		"https-wrench requests [flags]",
		// 		"--ca-bundle string",
		// 		"Usage:",
		// 		"--version         Display the version",
		// 	},
		// },
	}

	for _, tc := range tests {
		tt := tc

		t.Run(tt.name, func(t *testing.T) {
			reqOut := new(bytes.Buffer)
			reqCmd := rootCmd
			reqCmd.SetOut(reqOut)
			reqCmd.SetErr(reqOut)
			reqCmd.SetArgs(tt.args)
			err := reqCmd.Execute()

			if tt.expectError {
				require.Error(t, err)

				for _, expected := range tt.errMsgs {
					require.ErrorContains(t, err, expected)
				}

				// return
			}

			if !tt.expectError {
				require.NoError(t, err)
			}

			got := reqOut.String()
			for _, expexted := range tt.expected {
				require.Contains(t, got, expexted)
			}
		})
	}
}
