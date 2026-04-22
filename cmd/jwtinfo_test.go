package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJwtinfoCmd(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errMsgs     []string
		expected    []string
	}{
		{
			name:        "invalid file",
			args:        []string{"jwtinfo", "--token-file", "non_existent.jwt"},
			expectError: false,
			expected:    []string{"error while reading token value from file"},
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				rootCmd.Flags().Set("version", "false")
				jwtinfoCmd.Flags().Set("token-file", "")
				jwtinfoCmd.Flags().Set("clipboard", "false")
			})

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
			} else {
				require.NoError(t, err)
			}

			got := reqOut.String()
			for _, expected := range tt.expected {
				require.Contains(t, got, expected)
			}
		})
	}
}
