package cmd

import (
	"github.com/xenos76/https-wrench/internal/observability"
	"github.com/xenos76/https-wrench/internal/requests"
)

// HTTPSWrenchConfig represents the top-level configuration for the application.
type HTTPSWrenchConfig struct {
	// Debug enables detailed debug output across commands.
	Debug bool `mapstructure:"debug"`
	// Verbose enables verbose logging and formatted progress output.
	Verbose bool `mapstructure:"verbose"`
	// CaBundle provides an inline PEM-encoded CA certificate bundle.
	CaBundle string `mapstructure:"caBundle"`
	// Observability holds settings for continuous synthetic probing and metric exposition.
	Observability observability.Config `mapstructure:"observability"`
	// RequestsMetaConfig holds top-level HTTP client options and request definitions.
	requests.RequestsMetaConfig `mapstructure:",squash"`
}

// NewHTTPSWrenchConfig returns a new HTTPSWrenchConfig with default values.
func NewHTTPSWrenchConfig() *HTTPSWrenchConfig {
	c := HTTPSWrenchConfig{
		Observability: observability.DefaultConfig(),
	}

	return &c
}
