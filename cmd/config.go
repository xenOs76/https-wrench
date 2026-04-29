package cmd

import (
	"github.com/xenos76/https-wrench/internal/requests"
)

// HTTPSWrenchConfig represents the top-level configuration for the application.
type HTTPSWrenchConfig struct {
	Debug                       bool   `mapstructure:"debug"`
	Verbose                     bool   `mapstructure:"verbose"`
	CaBundle                    string `mapstructure:"caBundle"`
	requests.RequestsMetaConfig `mapstructure:",squash"`
}

// NewHTTPSWrenchConfig returns a new HTTPSWrenchConfig with default values.
func NewHTTPSWrenchConfig() *HTTPSWrenchConfig {
	c := HTTPSWrenchConfig{}
	return &c
}
