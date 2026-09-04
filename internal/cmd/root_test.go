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

func resetViper() {
	_ = rootCmd.PersistentFlags().Set("version", "false")
	_ = rootCmd.PersistentFlags().Set("config", "")

	viper.Reset()
	bindViperFlags()
}

//nolint:revive
func TestRootCmd_LoadConfig(t *testing.T) {
	t.Run("LoadConfig no config file", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			resetViper()
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

			resetViper()
		})

		var expectedCaCertsPool *x509.CertPool

		var expectedRequestsConfigs []requests.RequestConfig

		cfgFile = "./embedded/config-example.yaml"

		initConfig()

		config, err := LoadConfig()
		require.NoError(t, err)
		require.False(t, config.Debug)
		require.True(t, config.Verbose)
		// require.Empty(t, config.CaBundle)

		// testing mapstructure squash/embedding of requests.RequestsMetaConfig
		// into HTTPSWrenchConfig
		require.False(t, config.RequestDebug)
		require.False(t, config.RequestVerbose)
		require.IsType(t, expectedCaCertsPool, config.CACertsPool)
		require.IsType(t, expectedRequestsConfigs, config.Requests)

		// testing against the current values of the embedded config
		require.Equal(t, "SampleRequestAgainstLocalWebserver", config.Requests[0].Name)
		require.Equal(t, "https://127.0.0.1:9443", config.Requests[0].TransportOverrideURL)
	})

	t.Run("LoadConfig YAML anchor and merge keys", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			resetViper()
		})

		cfgFile = "../../assets/examples/https-wrench-k3s-anchor-and-aliases.yaml"

		initConfig()

		config, err := LoadConfig()
		require.NoError(t, err)
		require.True(t, config.Verbose)
		require.Len(t, config.Requests, 4)

		for _, req := range config.Requests {
			require.True(t, req.PrintResponseHeaders)
			require.Equal(t, []string{"Server"}, req.ResponseHeadersFilter)
			require.Len(t, req.Hosts, 1)
			require.Equal(t, "httpbingo.k3s.os76.xyz", req.Hosts[0].Name)
		}

		require.Equal(t, "k3sOs76ViaCaddyDnsDirect", config.Requests[0].Name)
		require.Empty(t, config.Requests[0].TransportOverrideURL)

		require.Equal(t, "k3sOs76NoLbShouldFail", config.Requests[1].Name)
		require.Equal(t, "https://rpi501.home.arpa", config.Requests[1].TransportOverrideURL)

		require.Equal(t, "k3sOs76ViaIstioDnsOverride", config.Requests[2].Name)
		require.Equal(t, "https://192.168.1.114:30443", config.Requests[2].TransportOverrideURL)

		require.Equal(t, "k3sOs76ViaNginxDnsOverride", config.Requests[3].Name)
		require.Equal(t, "https://argo.home.arpa", config.Requests[3].TransportOverrideURL)
	})

	t.Run("LoadConfig unmarshal error", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			resetViper()
		})

		// Make Unmarshal fail by setting a type mismatch
		viper.Set("Requests", "this is a string, not a slice")

		config, err := LoadConfig()
		require.Error(t, err)
		require.Nil(t, config)
		require.ErrorContains(t, err, "unable to decode into config struct")
	})
}

func TestRootCmd_Execute(t *testing.T) {
	t.Run("Execute empty config", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			rootCmd.SetArgs(nil)
		})

		cfgFile = ""

		rootCmd.SetArgs([]string{"--config"})

		initConfig()

		_, err := LoadConfig()

		require.NoError(t, err)
		err = Execute()
		require.EqualError(t, err, "flag needs an argument: --config")
	})

	t.Run("Execute success", func(t *testing.T) {
		oldCfg := cfgFile

		t.Cleanup(func() {
			cfgFile = oldCfg

			rootCmd.SetArgs(nil)
			resetViper()
		})

		rootCmd.SetArgs([]string{"--config", "./embedded/config-example.yaml"})

		err := Execute()
		require.NoError(t, err)
	})
}

//nolint:revive

//nolint:revive
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

				resetViper()
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
