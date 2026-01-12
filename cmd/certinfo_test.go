package cmd

import (
	"bytes"
	_ "embed"
	"testing"

	_ "github.com/breml/rootcerts"
	"github.com/stretchr/testify/require"
)

func TestCertinfoCmd(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errMsgs     []string
		expected    []string
	}{
		{
			name:        "no args",
			args:        []string{"certinfo"},
			expectError: false,
			expected: []string{
				"https-wrench certinfo",
				"Usage:",
				"Flags:",
				"Global Flags:",
				"--key-file",
				"--tls-endpoint",
				"--tls-insecure",
				"--tls-servername",
				"--ca-bundle",
				"--version",
				"--help",
			},
		},
		{
			name:        "key-file flag no value",
			args:        []string{"certinfo", "--key-file"},
			expectError: true,
			errMsgs: []string{
				"flag needs an argument: --key-file",
			},
			expected: []string{
				"https-wrench certinfo [flags]",
				"--ca-bundle string",
				"--key-file string",
				"--tls-endpoint string",
				"--tls-insecure",
				"--tls-servername string",
				"Usage:",
				"--version         Display the version",
			},
		},

		{
			name:        "tls-endpoint flag no value",
			args:        []string{"certinfo", "--tls-endpoint"},
			expectError: true,
			errMsgs: []string{
				"flag needs an argument: --tls-endpoint",
			},
			expected: []string{
				"https-wrench certinfo [flags]",
				"--ca-bundle string",
				"--key-file string",
				"--tls-endpoint string",
				"--tls-insecure",
				"--tls-servername string",
				"Usage:",
				"--version         Display the version",
			},
		},

		{
			name:        "tls-insecure incomplete params",
			args:        []string{"certinfo", "--tls-insecure"},
			expectError: false,
			expected: []string{
				"https-wrench certinfo [flags]",
				"--ca-bundle string",
				"--key-file string",
				"--tls-endpoint string",
				"--tls-insecure",
				"--tls-servername string",
				"Usage:",
				"--version         Display the version",
			},
		},
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
