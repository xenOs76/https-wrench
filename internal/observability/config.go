// Package observability implements continuous synthetic HTTPS probing and metrics
// exposition via Prometheus pull, Prometheus remote_write push, and OpenTelemetry OTLP/HTTP.
package observability

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	// DefaultInterval is the default duration between probe executions.
	DefaultInterval = 30 * time.Second
	// DefaultTimeout is the default maximum duration for a single probe cycle.
	DefaultTimeout = 25 * time.Second
	// DefaultPullAddress is the default address for the pull HTTP scrape server.
	DefaultPullAddress = "127.0.0.1:9090"
	// DefaultPullPath is the default path for Prometheus metrics exposition.
	DefaultPullPath = "/metrics"
	// DefaultPushTimeout is the default HTTP request timeout for push exporters.
	DefaultPushTimeout = 10 * time.Second
)

// Config holds all configuration for continuous observability mode.
type Config struct {
	// Enabled toggles continuous synthetic monitoring.
	Enabled bool `mapstructure:"enabled"`
	// Interval is the frequency between probe execution cycles.
	Interval time.Duration `mapstructure:"interval"`
	// Timeout is the maximum duration allowed for a single probe cycle.
	Timeout time.Duration `mapstructure:"timeout"`
	// Pull configures the embedded Prometheus HTTP scrape server.
	Pull PullConfig `mapstructure:"pull"`
	// Push configures remote telemetry push destinations.
	Push PushConfig `mapstructure:"push"`
	// Metrics controls metric filtering and custom labels.
	Metrics MetricsFilterConfig `mapstructure:"metrics"`
}

// PullConfig configures the Prometheus pull HTTP scrape server.
type PullConfig struct {
	// Enabled controls whether the pull server is started.
	Enabled bool `mapstructure:"enabled"`
	// Address is the host:port listening address for the scrape server.
	Address string `mapstructure:"address"`
	// Path is the HTTP URL path where Prometheus metrics are exposed.
	Path string `mapstructure:"path"`
	// ReloadToken is the bearer token required for POST /-/reload requests.
	ReloadToken string `mapstructure:"reloadToken"`
	// ReloadSecret is a fallback authorization secret for reload requests.
	ReloadSecret string `mapstructure:"reloadSecret"`
}

// ReloadAuthToken returns the configured reload credential if any, trimmed of whitespace.
func (p PullConfig) ReloadAuthToken() string {
	if token := strings.TrimSpace(p.ReloadToken); token != "" {
		return token
	}

	return strings.TrimSpace(p.ReloadSecret)
}

// PushConfig configures push destinations (Prometheus remote_write and/or OpenTelemetry OTLP).
type PushConfig struct {
	// Prometheus configures the Prometheus remote_write exporter.
	Prometheus PushPrometheusConfig `mapstructure:"prometheus"`
	// OTLP configures the OpenTelemetry OTLP/HTTP exporter.
	OTLP PushOTLPConfig `mapstructure:"otlp"`
}

// MetricsFilterConfig configures which metrics to produce and custom label additions.
type MetricsFilterConfig struct {
	// IncludeTLS enables TLS version, cipher suite, and certificate expiration metrics.
	IncludeTLS bool `mapstructure:"includeTls"`
	// IncludeCertChain exports expiration and validity metrics for the entire certificate chain.
	IncludeCertChain bool `mapstructure:"includeCertChain"`
	// StripQuery strips URL query parameters from the uri metric label to prevent cardinality explosion.
	StripQuery bool `mapstructure:"stripQuery"`
	// CustomLabels adds static key/value labels to all exported metrics.
	CustomLabels map[string]string `mapstructure:"customLabels"`
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

	if err := c.validatePull(); err != nil {
		return err
	}

	if err := c.validatePushPrometheus(); err != nil {
		return err
	}

	if err := c.validatePushOTLP(); err != nil {
		return err
	}

	if err := c.validateCustomLabels(); err != nil {
		return err
	}

	return c.validateModes()
}

// validateIntervalAndTimeout sets defaults and guarantees that timeout does not exceed interval.
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

// reservedPullPaths lists HTTP endpoint paths reserved for internal health and management handlers.
var reservedPullPaths = [...]string{"/healthz", "/readyz", "/-/reload"}

// validatePull applies defaults and validates the pull scrape endpoint path.
func (c *Config) validatePull() error {
	if !c.Pull.Enabled {
		return nil
	}

	if c.Pull.Address == "" {
		c.Pull.Address = DefaultPullAddress
	}

	if c.Pull.Path == "" {
		c.Pull.Path = DefaultPullPath
	}

	return validatePullPath(c.Pull.Path)
}

// validatePullPath ensures the pull path does not conflict with reserved endpoints or invalid patterns.
func validatePullPath(path string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("observability: invalid pull.path %q: %v", path, r)
		}
	}()

	patternPath := path
	if idx := strings.IndexByte(path, ' '); idx != -1 {
		patternPath = path[idx+1:]
	}

	if hostIdx := strings.IndexByte(patternPath, '/'); hostIdx != -1 {
		patternPath = patternPath[hostIdx:]
	}

	for _, reserved := range reservedPullPaths {
		if patternPath == reserved {
			return fmt.Errorf("observability: pull.path %q conflicts with reserved endpoint %s", path, reserved)
		}
	}

	mux := http.NewServeMux()
	mux.Handle(path, http.NotFoundHandler())

	for _, reserved := range reservedPullPaths {
		mux.Handle(reserved, http.NotFoundHandler())
	}

	return nil
}

// validatePushPrometheus ensures the destination URL is specified and sets default timeout if omitted.
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

// validatePushOTLP ensures the OTLP endpoint is specified and sets default protocol and timeout if omitted.
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

// validateModes ensures that when observability is enabled, at least one exporter or scrape server is active.
func (c *Config) validateModes() error {
	if c.Enabled && !c.Pull.Enabled && !c.Push.Prometheus.Enabled && !c.Push.OTLP.Enabled {
		return errors.New(
			"observability: at least one propagation mode (pull, push.prometheus, push.otlp) must be enabled",
		)
	}

	return nil
}

// reservedCollectorLabels defines Prometheus metric label names that cannot be overridden by custom labels.
var reservedCollectorLabels = map[string]struct{}{
	"body_match":        {},
	"chain_index":       {},
	"cipher_suite":      {},
	"exporter":          {},
	"host":              {},
	"key_exchange":      {},
	"method":            {},
	"regexp":            {},
	"request_name":      {},
	"result":            {},
	"status_code":       {},
	"tls_version":       {},
	"transport_address": {},
	"uri":               {},
}

// validateCustomLabels ensures configured custom labels do not conflict with reserved collector labels.
func (c *Config) validateCustomLabels() error {
	if len(c.Metrics.CustomLabels) == 0 {
		return nil
	}

	keys := make([]string, 0, len(c.Metrics.CustomLabels))

	for k := range c.Metrics.CustomLabels {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	for _, name := range keys {
		if _, exists := reservedCollectorLabels[name]; exists {
			return fmt.Errorf("observability: metrics.customLabels %q conflicts with reserved collector label", name)
		}
	}

	return nil
}
