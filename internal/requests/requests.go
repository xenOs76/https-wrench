package requests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
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

	emptyString = ""
)

var ErrMethodNotFound = errors.New("HTTP method not found")

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

type RequestHTTPClient struct {
	client             *http.Client
	method             string
	enableProxyProtoV2 bool
	transportAddress   string
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

type RequestsMetaConfig struct {
	RequestDebug   bool
	RequestVerbose bool
	CACertsPool    *x509.CertPool
	Requests       []RequestConfig `mapstructure:"requests"`
}

func NewRequestsMetaConfig() (*RequestsMetaConfig, error) {
	defaultCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	c := RequestsMetaConfig{
		CACertsPool: defaultCertPool,
	}

	return &c, nil
}

func (r *RequestsMetaConfig) SetVerbose(b bool) *RequestsMetaConfig {
	r.RequestVerbose = b
	return r
}

func (r *RequestsMetaConfig) SetDebug(b bool) *RequestsMetaConfig {
	r.RequestDebug = b
	return r
}

func (r *RequestsMetaConfig) SetCaPoolFromYAML(s string) error {
	if s != "" {
		certsPool, err := certinfo.GetRootCertsFromString(s)
		if err != nil {
			return errors.New("unable to create CA Certs Pool from YAML")
		}

		r.CACertsPool = certsPool
	}

	return nil
}

func (r *RequestsMetaConfig) SetCaPoolFromFile(filePath string) error {
	if filePath != "" {
		caCertsPool, err := certinfo.GetRootCertsFromFile(filePath)
		if err != nil {
			return err
		}

		r.CACertsPool = caCertsPool
	}

	return nil
}

func (r *RequestsMetaConfig) SetRequests(requests []RequestConfig) *RequestsMetaConfig {
	r.Requests = requests
	return r
}

func NewRequestHTTPClient() *RequestHTTPClient {
	tlsConfig := &tls.Config{}
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          transportMaxIdleConns,
			IdleConnTimeout:       transportIdleConnTimeout,
			TLSHandshakeTimeout:   transportTLSHandshakeTimeout,
			ResponseHeaderTimeout: transportResponseHeaderTimeout,
			ExpectContinueTimeout: transportExpectContinueTimeout,
			TLSClientConfig:       tlsConfig,
		},
		Timeout: httpClientTimeout,
	}

	requestClient := RequestHTTPClient{client: httpClient}

	return &requestClient
}

func (rc *RequestHTTPClient) SetServerName(serverName string) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", rc.client.Transport)
	}

	tr := transport.Clone()
	tr.TLSClientConfig.ServerName = serverName

	rc.client = &http.Client{
		Transport: tr,
		Timeout:   rc.client.Timeout,
	}

	return rc, nil
}

func (rc *RequestHTTPClient) SetCACertsPool(caPool *x509.CertPool) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	if caPool == nil {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("SetCACertsPool error: %w ", err)
		}

		caPool = systemCertPool
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", rc.client.Transport)
	}

	tr := transport.Clone()
	tr.TLSClientConfig.RootCAs = caPool

	rc.client = &http.Client{
		Transport: tr,
		Timeout:   rc.client.Timeout,
	}

	return rc, nil
}

func (rc *RequestHTTPClient) SetInsecureSkipVerify(isInsecure bool) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", rc.client.Transport)
	}

	tr := transport.Clone()
	tr.TLSClientConfig.InsecureSkipVerify = isInsecure

	rc.client = &http.Client{
		Transport: tr,
		Timeout:   rc.client.Timeout,
	}

	return rc, nil
}

func (rc *RequestHTTPClient) SetMethod(method string) (*RequestHTTPClient, error) {
	if method == emptyString {
		rc.method = httpClientDefaultMethod
		return rc, nil
	}

	allowedMethods := make(map[string]string)
	allowedMethods["GET"] = http.MethodGet
	allowedMethods["HEAD"] = http.MethodHead
	allowedMethods["POST"] = http.MethodPost
	allowedMethods["PUT"] = http.MethodPut
	allowedMethods["PATCH"] = http.MethodPatch
	allowedMethods["DELETE"] = http.MethodDelete
	allowedMethods["CONNECT"] = http.MethodConnect
	allowedMethods["OPTIONS"] = http.MethodOptions
	allowedMethods["TRACE"] = http.MethodTrace

	m := strings.ToUpper(method)

	if _, ok := allowedMethods[m]; ok {
		rc.method = m
		return rc, nil
	}

	return rc, fmt.Errorf("%s: %w", method, ErrMethodNotFound)
}

func (rc *RequestHTTPClient) SetTransportOverride(transportURL string) (*RequestHTTPClient, error) {
	if transportURL == emptyString {
		return rc, nil
	}

	if rc.client == nil {
		return nil, errors.New("*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	transportAddress, err := transportAddressFromURLString(transportURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transport override url: %s", transportURL)
	}

	rc.transportAddress = transportAddress

	dialer := &net.Dialer{
		Timeout:   httpClientTimeout,
		KeepAlive: httpClientKeepalive,
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", rc.client.Transport)
	}

	tr := transport.Clone()

	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, transportAddress)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

	rc.client = &http.Client{
		Transport: tr,
		Timeout:   rc.client.Timeout,
	}

	return rc, nil
}

func (rc *RequestHTTPClient) SetProxyProtocolV2(header proxyproto.Header) (*RequestHTTPClient, error) {
	if rc.transportAddress == emptyString {
		return nil, errors.New("SetProxyProtocolV2 failed: transportOverrideURL not set")
	}

	if rc.client == nil {
		return nil, errors.New("*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	dialer := &net.Dialer{
		Timeout:   httpClientTimeout,
		KeepAlive: httpClientKeepalive,
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", rc.client.Transport)
	}

	tr := transport.Clone()

	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, rc.transportAddress)
		if err != nil {
			return nil, err
		}

		if _, err = header.WriteTo(conn); err != nil {
			conn.Close()

			return nil, fmt.Errorf("failed to write PROXY header: %w", err)
		}

		return conn, nil
	}

	rc.client = &http.Client{
		Transport: tr,
		Timeout:   rc.client.Timeout,
	}

	return rc, nil
}

func (rc *RequestHTTPClient) SetClientTimeout(timeout int) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New("*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	t := time.Duration(timeout) * time.Second
	rc.client.Timeout = t

	return rc, nil
}

func NewHTTPClientFromRequest(r RequestConfig, serverName string, caPool *x509.CertPool) (*RequestHTTPClient, error) {
	if r.EnableProxyProtocolV2 && r.TransportOverrideURL == emptyString {
		return nil, errors.New(
			"if EnableProxyProtocolV2 is true, a TransportOverrideURL must be set")
	}

	reqClient := NewRequestHTTPClient()

	_, err := reqClient.SetCACertsPool(caPool)
	if err != nil {
		return nil, fmt.Errorf("SetCACertsPool error: %w", err)
	}

	_, err = reqClient.SetInsecureSkipVerify(r.Insecure)
	if err != nil {
		return nil, fmt.Errorf("SetInsecureSkipVerify error: %w", err)
	}

	_, err = reqClient.SetClientTimeout(r.ClientTimeout)
	if err != nil {
		return nil, fmt.Errorf("SetClientTimeout error: %w", err)
	}

	_, err = reqClient.SetMethod(r.RequestMethod)
	if err != nil {
		return nil, fmt.Errorf("SetMethod error: %w", err)
	}

	_, err = reqClient.SetServerName(serverName)
	if err != nil {
		return nil, fmt.Errorf("SetServerName error: %w", err)
	}

	_, err = reqClient.SetTransportOverride(r.TransportOverrideURL)
	if err != nil {
		return nil, fmt.Errorf("SetTransportOverride error: %w", err)
	}

	if r.EnableProxyProtocolV2 && reqClient.transportAddress != emptyString {
		header, err := proxyProtoHeaderFromRequest(r, serverName)
		if err != nil {
			return nil, fmt.Errorf("error creating proxyproto Header: %w", err)
		}

		_, err = reqClient.SetProxyProtocolV2(header)
		if err != nil {
			return nil, fmt.Errorf("SetProxyProtocolV2 error: %w", err)
		}
	}

	return reqClient, nil
}
