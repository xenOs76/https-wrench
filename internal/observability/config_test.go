package observability

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_DefaultsAndValidation(t *testing.T) {
	t.Parallel()

	t.Run("default config is valid", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		require.NoError(t, cfg.Validate())
		assert.Equal(t, DefaultInterval, cfg.Interval)
		assert.Equal(t, DefaultTimeout, cfg.Timeout)
		assert.Equal(t, DefaultPullAddress, cfg.Pull.Address)
		assert.Equal(t, DefaultPullPath, cfg.Pull.Path)
	})

	t.Run("clamps timeout to interval if timeout exceeds interval", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Interval = 10 * time.Second
		cfg.Timeout = 20 * time.Second
		require.NoError(t, cfg.Validate())
		assert.Equal(t, 10*time.Second, cfg.Timeout)
	})

	t.Run("requires remoteWriteUrl when prometheus push is enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Push.Prometheus.Enabled = true
		cfg.Push.Prometheus.RemoteWriteURL = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "push.prometheus.remoteWriteUrl is required")
	})

	t.Run("requires endpoint when otlp push is enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Push.OTLP.Enabled = true
		cfg.Push.OTLP.Endpoint = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "push.otlp.endpoint is required")
	})

	t.Run("requires at least one mode when enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Pull.Enabled = false
		cfg.Push.Prometheus.Enabled = false
		cfg.Push.OTLP.Enabled = false
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one propagation mode")
	})
}

func TestConfig_ValidatePullPath(t *testing.T) {
	t.Parallel()

	t.Run("empty path falls back to default pull path", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Pull.Path = ""
		require.NoError(t, cfg.Validate())
		assert.Equal(t, DefaultPullPath, cfg.Pull.Path)
	})

	t.Run("valid custom path succeeds", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Pull.Path = "/custom/metrics"
		require.NoError(t, cfg.Validate())
		assert.Equal(t, "/custom/metrics", cfg.Pull.Path)
	})

	for _, reserved := range []string{"/healthz", "/readyz", "/-/reload", "GET /healthz", "POST /-/reload"} {
		t.Run("rejects reserved path "+reserved, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.Pull.Path = reserved
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "conflicts with reserved endpoint")
		})
	}

	for _, malformed := range []string{"invalid-no-leading-slash", "/metrics/{bad"} {
		t.Run("rejects malformed pattern "+malformed, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.Pull.Path = malformed
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid pull.path")
		})
	}
}

func TestConfig_ValidateCustomLabels(t *testing.T) {
	t.Parallel()

	t.Run("valid custom labels succeed", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Metrics.CustomLabels = map[string]string{
			"env":     "production",
			"cluster": "us-east-1",
			"app":     "test",
		}
		require.NoError(t, cfg.Validate())
	})

	conflictingLabels := []string{
		"host",
		"uri",
		"request_name",
		"method",
		"status_code",
		"exporter",
		"transport_address",
		"body_match",
		"chain_index",
		"tls_version",
	}

	for _, label := range conflictingLabels {
		t.Run("rejects conflicting custom label "+label, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.Metrics.CustomLabels = map[string]string{
				label: "invalid-value",
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "conflicts with reserved collector label")
		})
	}

	t.Run("allows subject and matched_value as custom labels", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Metrics.CustomLabels = map[string]string{
			"subject":       "custom-subject",
			"matched_value": "custom-val",
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("NewRunner rejects conflicting custom labels without panicking", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.Metrics.CustomLabels = map[string]string{
			"host": "conflict-value",
		}
		runner, err := NewRunner(cfg, nil)
		require.Error(t, err)
		assert.Nil(t, runner)
		assert.Contains(t, err.Error(), "conflicts with reserved collector label")
	})
}

func TestPullConfig_ReloadAuthToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      PullConfig
		expected string
	}{
		{
			name:     "both empty",
			cfg:      PullConfig{},
			expected: "",
		},
		{
			name: "reload token trimmed when present",
			cfg: PullConfig{
				ReloadToken: "  my-token  ",
			},
			expected: "my-token",
		},
		{
			name: "reload token takes precedence over reload secret",
			cfg: PullConfig{
				ReloadToken:  "  my-token  ",
				ReloadSecret: "  my-secret ",
			},
			expected: "my-token",
		},
		{
			name: "whitespace reload token falls back to trimmed reload secret",
			cfg: PullConfig{
				ReloadToken:  "   \t  \n ",
				ReloadSecret: "  fallback-secret  ",
			},
			expected: "fallback-secret",
		},
		{
			name: "empty reload token falls back to trimmed reload secret",
			cfg: PullConfig{
				ReloadSecret: "  secret-value  ",
			},
			expected: "secret-value",
		},
		{
			name: "both whitespace only returns empty",
			cfg: PullConfig{
				ReloadToken:  "   ",
				ReloadSecret: "   ",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.ReloadAuthToken())
		})
	}
}
