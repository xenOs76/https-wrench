package observability

import (
	"errors"
	"time"
)

const (
	// DefaultInterval is the default duration between probe executions.
	DefaultInterval = 30 * time.Second
	// DefaultTimeout is the default maximum duration for a single probe cycle.
	DefaultTimeout = 25 * time.Second
	// DefaultPullAddress is the default address for the pull HTTP scrape server.
	DefaultPullAddress = ":9090"
	// DefaultPullPath is the default path for Prometheus metrics exposition.
	DefaultPullPath = "/metrics"
	// DefaultPushTimeout is the default HTTP request timeout for push exporters.
	DefaultPushTimeout = 10 * time.Second
)

// Config holds all configuration for continuous observability mode.
type Config struct {
	Enabled  bool                `mapstructure:"enabled"`
	Interval time.Duration       `mapstructure:"interval"`
	Timeout  time.Duration       `mapstructure:"timeout"`
	Pull     PullConfig          `mapstructure:"pull"`
	Push     PushConfig          `mapstructure:"push"`
	Metrics  MetricsFilterConfig `mapstructure:"metrics"`
}

// PullConfig configures the Prometheus pull HTTP scrape server.
type PullConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Address string `mapstructure:"address"`
	Path    string `mapstructure:"path"`
}

// PushConfig configures push destinations (Prometheus remote_write and/or OpenTelemetry OTLP).
type PushConfig struct {
	Prometheus PushPrometheusConfig `mapstructure:"prometheus"`
	OTLP       PushOTLPConfig       `mapstructure:"otlp"`
}

// MetricsFilterConfig configures which metrics to produce and custom label additions.
type MetricsFilterConfig struct {
	IncludeTLS       bool              `mapstructure:"includeTls"`
	IncludeCertChain bool              `mapstructure:"includeCertChain"`
	StripQuery       bool              `mapstructure:"stripQuery"`
	CustomLabels     map[string]string `mapstructure:"customLabels"`
}

// DefaultConfig returns a Config initialized with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:  false,
		Interval: DefaultInterval,
		Timeout:  DefaultTimeout,
		Pull: PullConfig{
			Enabled: true,
			Address: DefaultPullAddress,
			Path:    DefaultPullPath,
		},
		Push: PushConfig{
			Prometheus: PushPrometheusConfig{
				Timeout: DefaultPushTimeout,
			},
			OTLP: PushOTLPConfig{
				Timeout:  DefaultPushTimeout,
				Protocol: "http/protobuf",
			},
		},
		Metrics: MetricsFilterConfig{
			IncludeTLS:       true,
			IncludeCertChain: false,
			StripQuery:       true,
		},
	}
}

// Validate verifies and sets sensible defaults for Config.
func (c *Config) Validate() error {
	c.validateIntervalAndTimeout()
	c.validatePull()

	if err := c.validatePushPrometheus(); err != nil {
		return err
	}

	if err := c.validatePushOTLP(); err != nil {
		return err
	}

	return c.validateModes()
}

func (c *Config) validateIntervalAndTimeout() {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}

	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}

	if c.Timeout > c.Interval {
		c.Timeout = c.Interval
	}
}

func (c *Config) validatePull() {
	if !c.Pull.Enabled {
		return
	}

	if c.Pull.Address == "" {
		c.Pull.Address = DefaultPullAddress
	}

	if c.Pull.Path == "" {
		c.Pull.Path = DefaultPullPath
	}
}

func (c *Config) validatePushPrometheus() error {
	if !c.Push.Prometheus.Enabled {
		return nil
	}

	if c.Push.Prometheus.RemoteWriteURL == "" {
		return errors.New("observability: push.prometheus.remoteWriteUrl is required when enabled")
	}

	if c.Push.Prometheus.Timeout <= 0 {
		c.Push.Prometheus.Timeout = DefaultPushTimeout
	}

	return nil
}

func (c *Config) validatePushOTLP() error {
	if !c.Push.OTLP.Enabled {
		return nil
	}

	if c.Push.OTLP.Endpoint == "" {
		return errors.New("observability: push.otlp.endpoint is required when enabled")
	}

	if c.Push.OTLP.Timeout <= 0 {
		c.Push.OTLP.Timeout = DefaultPushTimeout
	}

	if c.Push.OTLP.Protocol == "" {
		c.Push.OTLP.Protocol = "http/protobuf"
	}

	return nil
}

func (c *Config) validateModes() error {
	if c.Enabled && !c.Pull.Enabled && !c.Push.Prometheus.Enabled && !c.Push.OTLP.Enabled {
		return errors.New(
			"observability: at least one propagation mode (pull, push.prometheus, push.otlp) must be enabled",
		)
	}

	return nil
}
