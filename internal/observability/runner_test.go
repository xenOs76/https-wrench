package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/requests"
)

func TestRunner_Lifecycle(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	}))
	defer ts.Close()

	reqMeta := &requests.RequestsMetaConfig{
		Requests: []requests.RequestConfig{
			{
				Name: "test-probe",
				Hosts: []requests.Host{
					{
						Name: "127.0.0.1",
						URIList: []requests.URI{
							"/",
						},
					},
				},
				TransportOverrideURL: ts.URL,
			},
		},
	}

	cfg := Config{
		Enabled:  true,
		Interval: 50 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
		Pull: PullConfig{
			Enabled: true,
			Address: "127.0.0.1:0",
			Path:    "/metrics",
		},
	}

	runner, err := NewRunner(cfg, reqMeta)
	require.NoError(t, err)
	require.NotNil(t, runner)

	// Test immediate execution
	ctx, cancel := context.WithCancel(context.Background())
	runner.ExecuteCycle(ctx)

	mfs, err := runner.Metrics().Registry().Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs)

	// Run runner for a short period then cancel
	runDone := make(chan error, 1)
	go func() {
		runDone <- runner.Run(ctx)
	}()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case runErr := <-runDone:
		require.NoError(t, runErr)
	case <-time.After(2 * time.Second):
		t.Fatal("runner failed to shut down within timeout")
	}
}

func newTestRunnerWithConfig(t *testing.T, reqName string, interval time.Duration) *Runner {
	t.Helper()

	meta := &requests.RequestsMetaConfig{
		Requests: []requests.RequestConfig{{Name: reqName}},
	}
	cfg := Config{
		Enabled:  true,
		Interval: interval,
		Timeout:  100 * time.Millisecond,
		Pull: PullConfig{
			Enabled: true,
			Address: "127.0.0.1:0",
			Path:    "/metrics",
		},
	}

	runner, err := NewRunner(cfg, meta)
	require.NoError(t, err)

	return runner
}

func TestRunner_Reload(t *testing.T) {
	t.Parallel()

	runner := newTestRunnerWithConfig(t, "req-v1", 100*time.Millisecond)

	// Reload before reloader is set should fail
	err := runner.Reload()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no reload function configured")

	updatedMeta := &requests.RequestsMetaConfig{
		Requests: []requests.RequestConfig{{Name: "req-v2"}},
	}
	updatedCfg := &Config{
		Enabled:  true,
		Interval: 250 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
		Pull: PullConfig{
			Enabled: true,
			Address: "127.0.0.1:0",
			Path:    "/metrics",
		},
	}

	shouldFail := false

	runner.SetReloader("", func() (*Config, *requests.RequestsMetaConfig, error) {
		if shouldFail {
			return nil, nil, errors.New("simulated reload failure")
		}

		return updatedCfg, updatedMeta, nil
	})

	// Successful reload
	err = runner.Reload()
	require.NoError(t, err)

	runner.mu.RLock()
	assert.Equal(t, 250*time.Millisecond, runner.cfg.Interval)
	assert.Equal(t, "req-v2", runner.reqMeta.Requests[0].Name)
	runner.mu.RUnlock()

	// Check that interval channel received the new interval
	select {
	case newInt := <-runner.intervalCh:
		assert.Equal(t, 250*time.Millisecond, newInt)
	default:
		t.Fatal("expected new interval on intervalCh")
	}

	// Unsuccessful reload: retains previous state
	shouldFail = true
	err = runner.Reload()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated reload failure")

	runner.mu.RLock()
	assert.Equal(t, "req-v2", runner.reqMeta.Requests[0].Name)
	runner.mu.RUnlock()
}

func TestRunner_Reload_RejectNonReloadablePull(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modifyCfg func(cfg *Config)
	}{
		{
			name: "reject pull address change",
			modifyCfg: func(cfg *Config) {
				cfg.Pull.Address = "127.0.0.1:9099"
			},
		},
		{
			name: "reject pull path change",
			modifyCfg: func(cfg *Config) {
				cfg.Pull.Path = "/other-metrics"
			},
		},
		{
			name: "reject pull enabled state change",
			modifyCfg: func(cfg *Config) {
				cfg.Pull.Enabled = false
				cfg.Push.OTLP.Enabled = true
				cfg.Push.OTLP.Endpoint = "http://127.0.0.1:4318"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runner := newTestRunnerWithConfig(t, "req-v1", 100*time.Millisecond)

			initialCfg := runner.cfg
			targetCfg := runner.cfg
			tt.modifyCfg(&targetCfg)

			runner.SetReloader("", func() (*Config, *requests.RequestsMetaConfig, error) {
				cfgCopy := targetCfg

				return &cfgCopy, &requests.RequestsMetaConfig{
					Requests: []requests.RequestConfig{{Name: "req-rejected"}},
				}, nil
			})

			err := runner.Reload()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "pull configuration (address, path, enabled)")

			runner.mu.RLock()
			assert.Equal(t, initialCfg.Pull.Address, runner.cfg.Pull.Address)
			assert.Equal(t, initialCfg.Pull.Path, runner.cfg.Pull.Path)
			assert.Equal(t, initialCfg.Pull.Enabled, runner.cfg.Pull.Enabled)
			assert.Equal(t, "req-v1", runner.reqMeta.Requests[0].Name)
			runner.mu.RUnlock()
		})
	}
}

func TestRunner_Reload_RejectNonReloadableMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modifyCfg func(cfg *Config)
	}{
		{
			name: "reject metrics custom labels change",
			modifyCfg: func(cfg *Config) {
				cfg.Metrics.CustomLabels = map[string]string{"env": "test"}
			},
		},
		{
			name: "reject metrics includeTls filter change",
			modifyCfg: func(cfg *Config) {
				cfg.Metrics.IncludeTLS = !cfg.Metrics.IncludeTLS
			},
		},
		{
			name: "reject metrics includeCertChain filter change",
			modifyCfg: func(cfg *Config) {
				cfg.Metrics.IncludeCertChain = !cfg.Metrics.IncludeCertChain
			},
		},
		{
			name: "reject metrics stripQuery filter change",
			modifyCfg: func(cfg *Config) {
				cfg.Metrics.StripQuery = !cfg.Metrics.StripQuery
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runner := newTestRunnerWithConfig(t, "req-v1", 100*time.Millisecond)

			initialCfg := runner.cfg
			targetCfg := runner.cfg
			tt.modifyCfg(&targetCfg)

			runner.SetReloader("", func() (*Config, *requests.RequestsMetaConfig, error) {
				cfgCopy := targetCfg

				return &cfgCopy, &requests.RequestsMetaConfig{
					Requests: []requests.RequestConfig{{Name: "req-rejected"}},
				}, nil
			})

			err := runner.Reload()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "metrics configuration (labels, filters)")

			runner.mu.RLock()
			assert.Equal(t, initialCfg.Metrics, runner.cfg.Metrics)
			assert.Equal(t, "req-v1", runner.reqMeta.Requests[0].Name)
			runner.mu.RUnlock()
		})
	}
}

func TestRunner_FileModificationReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "probe-config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("version: 1\n"), 0o600))

	runner := newTestRunnerWithConfig(t, "req-v1", 100*time.Millisecond)

	reloadCalls := 0
	currentReqName := "req-v1"

	runner.SetReloader(cfgFile, func() (*Config, *requests.RequestsMetaConfig, error) {
		reloadCalls++

		content, readErr := os.ReadFile(cfgFile)
		if readErr != nil {
			return nil, nil, readErr
		}

		if string(content) == "invalid-syntax" {
			return nil, nil, errors.New("yaml parse error")
		}

		cfg := &Config{
			Enabled:  true,
			Interval: 100 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Pull: PullConfig{
				Enabled: true,
				Address: "127.0.0.1:0",
				Path:    "/metrics",
			},
		}
		meta := &requests.RequestsMetaConfig{
			Requests: []requests.RequestConfig{{Name: currentReqName}},
		}

		return cfg, meta, nil
	})

	// 1. First check: file unmodified from initial hash recorded in SetReloader
	runner.checkFileModification()
	assert.Equal(t, 0, reloadCalls)

	// 2. Modify file on disk
	currentReqName = "req-v2"

	require.NoError(t, os.WriteFile(cfgFile, []byte("version: 2\n"), 0o600))

	runner.checkFileModification()
	assert.Equal(t, 1, reloadCalls)
	runner.mu.RLock()
	assert.Equal(t, "req-v2", runner.reqMeta.Requests[0].Name)
	runner.mu.RUnlock()

	// 3. Corrupt file: reload fails, fallback keeps req-v2
	require.NoError(t, os.WriteFile(cfgFile, []byte("invalid-syntax"), 0o600))
	runner.checkFileModification()
	assert.Equal(t, 2, reloadCalls)
	runner.mu.RLock()
	assert.Equal(t, "req-v2", runner.reqMeta.Requests[0].Name)
	runner.mu.RUnlock()
}
