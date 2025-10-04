package cmd

import (
	"net/http"
	"time"
)

type (
	URI            string
	ResponseHeader string
)

type Host struct {
	Name    string `mapstructure:"name"`
	URIList []URI  `mapstructure:"uriList"`
}

type RequestHeader struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

type RequestConfig struct {
	Name                      string          `mapstructure:"name"`
	ClientTimeout             time.Duration   `mapstructure:"clientTimeout"`
	UserAgent                 string          `mapstructure:"userAgent"`
	TransportOverrideURL      string          `mapstructure:"transportOverrideUrl"`
	EnableProxyProtocolV2     bool            `mapstructure:"enableProxyProtocolV2"`
	Insecure                  bool            `mapstructure:"insecure"`
	RequestDebug              bool            `mapstructure:"requestDebug"`
	RequestHeaders            []RequestHeader `mapstructure:"requestHeaders"`
	RequestMethod             string          `mapstructure:"requestMethod"`
	RequestBody               string          `mapstructure:"requestBody"`
	ResponseDebug             bool            `mapstructure:"responseDebug"`
	ResponseHeadersFilter     []string        `mapstructure:"responseHeadersFilter"`
	ResponseBodyMatchRegexp   string          `mapstructure:"responseBodyMatchRegexp"`
	PrintResponseBody         bool            `mapstructure:"printResponseBody"`
	PrintResponseHeaders      bool            `mapstructure:"printResponseHeaders"`
	PrintResponseCertificates bool            `mapstructure:"printResponseCertificates"`
	Hosts                     []Host          `mapstructure:"hosts"`
}

type ResponseData struct {
	Request                   RequestConfig
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
	Requests []RequestConfig `mapstructure:"requests"`
}
