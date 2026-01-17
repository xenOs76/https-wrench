package cmd

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"testing"

	_ "github.com/breml/rootcerts"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/requests"
)

func TestRootCmd_LoadConfig(t *testing.T) {
	t.Run("LoadConfig no config file", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			viper.Reset()
		})

		var mc requests.RequestsMetaConfig

		config, err := LoadConfig()
		require.NoError(t, err)
		require.False(t, config.Debug)
		require.False(t, config.Verbose)
		require.Empty(t, config.CaBundle)

		if diff := cmp.Diff(mc, config.RequestsMetaConfig); diff != "" {
			t.Errorf(
				"NewHTTPSWrenchConfig: RequestsMetaConfig mismatch (-want +got):\n%s",
				diff,
			)
		}
	})

	t.Run("LoadConfig embedded config file", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			viper.Reset()
		})

		var expectedCaCertsPool *x509.CertPool

		var expectedRequestsConfigs []requests.RequestConfig

		cfgFile = "./embedded/config-example.yaml"

		initConfig()

		config, err := LoadConfig()
		require.NoError(t, err)
		require.False(t, config.Debug)
		require.True(t, config.Verbose)
		require.Empty(t, config.CaBundle)

		// testing mapstructure squash/embedding of requests.RequestsMetaConfig
		// into HTTPSWrenchConfig
		require.False(t, config.RequestDebug)
		require.False(t, config.RequestVerbose)
		require.IsType(t, expectedCaCertsPool, config.CACertsPool)
		require.IsType(t, expectedRequestsConfigs, config.Requests)

		// testing against the current values of the embedded config
		require.Equal(t, "httpBunComGet", config.Requests[0].Name)
		require.Equal(t, "https://cat.httpbun.com:443", config.Requests[0].TransportOverrideURL)
	})
}

func TestRootCmd_Execute(t *testing.T) {
	t.Run("Execute empty config", func(t *testing.T) {
		cfgFile = ""

		initConfig()

		_, err := LoadConfig()

		require.NoError(t, err)
		Execute()
	})
}

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
			name:        "config flag valid arg",
			args:        []string{"--config", "./embedded/config-example.yaml"},
			expectError: false,
			// Unable to intercept the output
			expected: []string{},
		},

		{
			name:        "config flag not arg",
			args:        []string{"--config"},
			expectError: true,
			expected:    []string{"flag needs an argument: --config"},
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
			oldCfg := cfgFile

			t.Cleanup(func() {
				cfgFile = oldCfg

				viper.Reset()
			})

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
