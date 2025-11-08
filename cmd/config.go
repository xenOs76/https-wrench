package cmd

import (
	"github.com/xenos76/https-wrench/internal/requests"
)

type HTTPSWrenchConfig struct {
	Debug                       bool   `mapstructure:"debug"`
	Verbose                     bool   `mapstructure:"verbose"`
	CaBundle                    string `mapstructure:"caBundle"`
	requests.RequestsMetaConfig `mapstructure:",squash"`
}

func NewHTTPSWrenchConfig() *HTTPSWrenchConfig {
	c := HTTPSWrenchConfig{}
	return &c
}
