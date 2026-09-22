package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/breml/rootcerts"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/observability"
)

//nolint:revive
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
				"--concurrency",
				"--format",
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
				"concurrency:",
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
		{
			name:        "unsupported format",
			args:        []string{"requests", "--format", "invalid"},
			expectError: false,
			expected: []string{
				"Error: unsupported --format \"invalid\" (use text or json)",
			},
		},
	}

	for _, tc := range tests {
		tt := tc

		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, rootCmd.Flags().Set("version", "false"))
				require.NoError(t, requestsCmd.Flags().Set("ca-bundle", ""))
				require.NoError(t, rootCmd.Flags().Set("config", ""))
				require.NoError(t, requestsCmd.Flags().Set("show-sample-config", "false"))
				require.NoError(t, requestsCmd.Flags().Set("format", "text"))
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

func TestRequestsCmd_ShowSampleConfigStdout(t *testing.T) {
	t.Cleanup(func() {
		require.NoError(t, rootCmd.Flags().Set("version", "false"))
		require.NoError(t, requestsCmd.Flags().Set("ca-bundle", ""))
		require.NoError(t, rootCmd.Flags().Set("config", ""))
		require.NoError(t, requestsCmd.Flags().Set("show-sample-config", "false"))
		rootCmd.SetArgs(nil)
	})

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	reqCmd := rootCmd
	reqCmd.SetOut(stdout)
	reqCmd.SetErr(stderr)
	reqCmd.SetArgs([]string{"requests", "--show-sample-config"})

	err := reqCmd.Execute()
	require.NoError(t, err)

	// Verify that the output was written to stdout
	gotStdout := stdout.String()
	require.Contains(t, gotStdout, "https-wrench.schema.json")
	require.Contains(t, gotStdout, "requests:")

	// Verify that nothing was written to stderr
	gotStderr := stderr.String()
	require.Empty(t, gotStderr, "Expected stderr to be empty, but got: %s", gotStderr)
}

func setupRequestsCmdConfigFile(t *testing.T, targetURL string) string {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "requests.yaml")
	cfgContent := `verbose: true
requests:
  - name: test-cmd-req
    requestMethod: GET
    insecure: true
    printResponseBody: true
    printResponseHeaders: true
    transportOverrideUrl: "` + targetURL + `"
    hosts:
      - name: example.com
        uriList:
          - /
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	return cfgPath
}

func TestRequestsCmd_FormatJSONAndText(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	cfgPath := setupRequestsCmdConfigFile(t, ts.URL)

	t.Run("format json", func(t *testing.T) {
		t.Cleanup(func() {
			resetViper()

			cfgFile = ""

			require.NoError(t, requestsCmd.Flags().Set("format", "text"))

			rootCmd.SetArgs(nil)
		})

		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)

		reqCmd := rootCmd
		reqCmd.SetOut(stdout)
		reqCmd.SetErr(stderr)
		reqCmd.SetArgs([]string{"requests", "--config", cfgPath, "--format", "json"})

		err := reqCmd.Execute()
		require.NoError(t, err)

		out := stdout.String()
		require.Contains(t, out, `"schemaVersion": "1"`)
		require.Contains(t, out, `"command": "requests"`)
		require.Contains(t, out, `"name": "test-cmd-req"`)
		require.Contains(t, out, `"statusCode": 200`)
		require.NotContains(t, out, "\x1b[", "JSON output must not contain ANSI escape sequences")
	})

	t.Run("format text", func(t *testing.T) {
		t.Cleanup(func() {
			resetViper()

			cfgFile = ""

			require.NoError(t, requestsCmd.Flags().Set("format", "text"))

			rootCmd.SetArgs(nil)
		})

		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)

		reqCmd := rootCmd
		reqCmd.SetOut(stdout)
		reqCmd.SetErr(stderr)
		reqCmd.SetArgs([]string{"requests", "--config", cfgPath, "--format", "text"})

		err := reqCmd.Execute()
		require.NoError(t, err)

		out := stdout.String()
		require.Contains(t, out, "Requests")
		require.Contains(t, out, "Request: test-cmd-req")
		require.Contains(t, out, "StatusCode: 200 OK")
	})
}

func TestRequestsCmd_Observability(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "requests.yaml")

	yamlContent := fmt.Sprintf("verbose: false\nrequests:\n"+
		"  - name: obs-test\n    insecure: true\n    clientTimeout: 1\n"+
		"    transportOverrideUrl: %s\n    hosts:\n      - name: 127.0.0.1\n        uriList:\n          - /\n", ts.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0o600))

	t.Cleanup(func() {
		resetViper()

		cfgFile = ""
		_ = requestsCmd.Flags().Set("observe", "false")
		_ = requestsCmd.Flags().Set("interval", "0s")
		_ = requestsCmd.Flags().Set("listen", "")

		rootCmd.SetArgs(nil)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	reqCmd := rootCmd
	reqCmd.SetOut(stdout)
	reqCmd.SetErr(stderr)
	reqCmd.SetArgs([]string{
		"requests",
		"--config", cfgPath,
		"--observe",
		"--interval", "50ms",
		"--listen", "127.0.0.1:0",
	})

	done := make(chan error, 1)
	go func() {
		done <- reqCmd.ExecuteContext(ctx)
	}()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for requestsCmd to exit")
	}

	assert.Contains(t, stdout.String(), "scrape server listening")
}

func TestApplyObservabilityOverrides_Logging(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&observeLogLevel, "log-level", "", "")
	cmd.Flags().StringVar(&observeLogFormat, "log-format", "", "")

	require.NoError(t, cmd.Flags().Set("log-level", "debug"))
	require.NoError(t, cmd.Flags().Set("log-format", "json"))

	base := observability.DefaultConfig()
	obsCfg := applyObservabilityOverrides(base, cmd)

	assert.Equal(t, "debug", obsCfg.Logging.Level)
	assert.Equal(t, "json", obsCfg.Logging.Format)
}
