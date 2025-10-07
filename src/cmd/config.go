package cmd

import (
	"net/http"
)

type (
	uri            string
	responseHeader string
)

type host struct {
	Name    string `mapstructure:"name"`
	URIList []uri  `mapstructure:"uriList"`
}

type requestHeader struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

type requestConfig struct {
	Name                      string          `mapstructure:"name"`
	ClientTimeout             int             `mapstructure:"clientTimeout"`
	UserAgent                 string          `mapstructure:"userAgent"`
	TransportOverrideURL      string          `mapstructure:"transportOverrideUrl"`
	EnableProxyProtocolV2     bool            `mapstructure:"enableProxyProtocolV2"`
	Insecure                  bool            `mapstructure:"insecure"`
	RequestDebug              bool            `mapstructure:"requestDebug"`
	RequestHeaders            []requestHeader `mapstructure:"requestHeaders"`
	RequestMethod             string          `mapstructure:"requestMethod"`
	RequestBody               string          `mapstructure:"requestBody"`
	ResponseDebug             bool            `mapstructure:"responseDebug"`
	ResponseHeadersFilter     []string        `mapstructure:"responseHeadersFilter"`
	ResponseBodyMatchRegexp   string          `mapstructure:"responseBodyMatchRegexp"`
	PrintResponseBody         bool            `mapstructure:"printResponseBody"`
	PrintResponseHeaders      bool            `mapstructure:"printResponseHeaders"`
	PrintResponseCertificates bool            `mapstructure:"printResponseCertificates"`
	Hosts                     []host          `mapstructure:"hosts"`
}

type responseData struct {
	Request                   requestConfig
	TransportAddress          string
	URL                       string
	ResponseBody              string
	ResponseBodyRegexpMatched bool
	Response                  *http.Response
	Error                     error
}

type Config struct {
	Debug    bool            `mapstructure:"debug"`
	Verbose  bool            `mapstructure:"verbose"`
	CaBundle string          `mapstructure:"caBundle"`
	Requests []requestConfig `mapstructure:"requests"`
}
