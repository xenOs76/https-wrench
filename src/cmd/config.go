package cmd

import (
	"net/http"
	"time"
)

type (
	Uri            string
	ResponseHeader string
)

type Host struct {
	Name    string `mapstructure:"name"`
	UriList []Uri  `mapstructure:"uriList"`
}

type RequestHeader struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

type RequestConfig struct {
	Name                      string          `mapstructure:"name"`
	ClientTimeout             time.Duration   `mapstructure:"clientTimeout"`
	UserAgent                 string          `mapstructure:"userAgent"`
	TransportOverrideUrl      string          `mapstructure:"transportOverrideUrl"`
	EnableProxyProtocolV2     bool            `mapstructure:"enableProxyProtocolV2"`
	Insecure                  bool            `mapstructure:"insecure"`
	RequestDebug              bool            `mapstructure:"requestDebug"`
	RequestHeaders            []RequestHeader `mapstructure:"requestHeaders"`
	RequestMethod             string          `mapstructure:"requestMethod"`
	RequestBody               string          `mapstructure:"requestBody"`
	ResponseDebug             bool            `mapstructure:"responseDebug"`
	ResponseHeadersFilter     []string        `mapstructure:"responseHeadersFilter"`
	PrintResponseBody         bool            `mapstructure:"printResponseBody"`
	PrintResponseHeaders      bool            `mapstructure:"printResponseHeaders"`
	PrintResponseCertificates bool            `mapstructure:"printResponseCertificates"`
	Hosts                     []Host          `mapstructure:"hosts"`
}

type ResponseData struct {
	RequestName               string
	TransportAddress          string
	Url                       string
	PrintResponseBody         bool
	PrintResponseHeaders      bool
	PrintResponseCertificates bool
	ResponseHeadersFilter     []string
	ResponseBody              string
	Response                  *http.Response
	Error                     error
}

type Config struct {
	Debug    bool            `mapstructure:"debug"`
	Verbose  bool            `mapstructure:"verbose"`
	CaBundle string          `mapstructure:"caBundle"`
	Requests []RequestConfig `mapstructure:"requests"`
}
