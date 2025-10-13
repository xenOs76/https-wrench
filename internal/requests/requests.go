package requests

import (
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/xenos76/https-wrench/internal/certinfo"
)

const (
	httpUserAgent                         = "https-wrench-request"
	httpClientDefaultMethod               = "GET"
	httpClientTimeout       time.Duration = 30 * time.Second
	httpClientKeepalive     time.Duration = 30 * time.Second

	transportMaxIdleConns          int           = 100
	transportIdleConnTimeout       time.Duration = 30 * time.Second
	transportTLSHandshakeTimeout   time.Duration = 30 * time.Second
	transportResponseHeaderTimeout time.Duration = 30 * time.Second
	transportExpectContinueTimeout time.Duration = 1 * time.Second

	proxyProtoDefaultSrcIPv4 = "192.0.2.1"
	proxyProtoDefaultSrcIPv6 = "2001:db8::1"
	proxyProtoDefaultSrcPort = 54321
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
	ClientTimeout             int             `mapstructure:"clientTimeout"`
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

type RequestsConfig struct {
	RequestDebug   bool
	RequestVerbose bool
	CACertsPool    *x509.CertPool
	Requests       []RequestConfig `mapstructure:"requests"`
}

func NewRequestsConfig() (*RequestsConfig, error) {
	defaultCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	c := RequestsConfig{
		CACertsPool: defaultCertPool,
	}
	return &c, nil
}

func (r *RequestsConfig) SetVerbose(b bool) *RequestsConfig {
	r.RequestVerbose = b
	return r
}

func (r *RequestsConfig) SetDebug(b bool) *RequestsConfig {
	r.RequestDebug = b
	return r
}

func (r *RequestsConfig) SetCaPoolFromYAML(s string) error {
	if s != "" {
		certsPool, err := certinfo.GetRootCertsFromString(s)
		if err != nil {
			return errors.New("unable to create CA Certs Pool from YAML")
		}
		r.CACertsPool = certsPool
	}
	return nil
}

func (r *RequestsConfig) SetCaPoolFromFile(filePath string) error {
	if filePath != "" {
		caCertsPool, err := certinfo.GetRootCertsFromFile(filePath)
		if err != nil {
			return err
		}
		r.CACertsPool = caCertsPool
	}
	return nil
}

func (r *RequestsConfig) SetRequests(requests []RequestConfig) *RequestsConfig {
	r.Requests = requests
	return r
}
