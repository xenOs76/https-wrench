package requests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/style"
)

const (
	httpUserAgent                         = "https-wrench-request"
	httpClientDefaultMethod               = "GET"
	httpClientDefaultScheme               = "https"
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

var allowedHTTPMethods = map[string]string{
	"GET":     http.MethodGet,
	"HEAD":    http.MethodHead,
	"POST":    http.MethodPost,
	"PUT":     http.MethodPut,
	"PATCH":   http.MethodPatch,
	"DELETE":  http.MethodDelete,
	"CONNECT": http.MethodConnect,
	"OPTIONS": http.MethodOptions,
	"TRACE":   http.MethodTrace,
}

var contentTypeMatchingItems = []struct {
	language string
	regexp   string
}{
	{"html", "(?i)text/html"},
	{"json", "(?i)application/json"},
	{"csv", "(?i)text/csv"},
	{"yaml", "(?i)(application|text)/(yaml|x-yaml)"},
	{"xml", "(?i)(application|text)/xml"},
	{"javascript", "(?i)text/javascript"},
	{"css", "(?i)text/css"},
}

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

func (r *RequestsMetaConfig) PrintCmd() {
	if r.RequestVerbose {
		fmt.Println()
		fmt.Println(style.LgSprintf(style.Cmd, "Requests"))
		fmt.Println()
	}
}

func (r *RequestConfig) PrintTitle(isVerbose bool) {
	if isVerbose {
		fmt.Print(style.LgSprintf(style.TitleKey, "Request:"))
		fmt.Println(style.LgSprintf(style.Title, "%s", r.Name))

		if r.TransportOverrideURL != "" {
			fmt.Print(style.LgSprintf(style.ItemKey, "Via:"))
			fmt.Println(style.LgSprintf(style.Via, "%s", r.TransportOverrideURL))
		}
	}
}

func (r *RequestConfig) PrintRequestDebug(req *http.Request) {
	if r.RequestDebug {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Printf("Warning: failed to dump request: %v\n", err)
			return
		}

		fmt.Printf("Requesting url: %s\n", req.URL)
		fmt.Printf("Request dump:\n%s\n", string(reqDump))
	}
}

func (r *RequestConfig) PrintResponseDebug(resp *http.Response) {
	if r.ResponseDebug {
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			fmt.Printf("Warning: failed to dump response: %v\n", err)
			return
		}

		fmt.Printf("Requested url: %s\n", resp.Request.URL)
		fmt.Printf("Response dump:\n%s\n", string(respDump))

		if resp.TLS != nil {
			fmt.Println("TLS:")
			fmt.Printf("Version: %v\n", TLSVersionName(resp.TLS.Version))
			fmt.Printf("CipherSuite: %v\n", cipherSuiteName(resp.TLS.CipherSuite))

			for i, cert := range resp.TLS.PeerCertificates {
				fmt.Printf("Certificate %d:\n", i)
				certinfo.PrintCertInfo(cert, 1)
			}

			for i, chain := range resp.TLS.VerifiedChains {
				fmt.Printf("Verified Chain %d:\n", i)

				for j, cert := range chain {
					fmt.Printf(" Cert %d:\n", j)
					certinfo.PrintCertInfo(cert, 2)
				}
			}
		} else {
			fmt.Println("TLS: Not available (non-TLS connection)")
		}
	}
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

	m := strings.ToUpper(method)

	if _, ok := allowedHTTPMethods[m]; ok {
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
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
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
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
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
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	t := time.Duration(timeout) * time.Second
	rc.client.Timeout = t

	return rc, nil
}

func NewHTTPClientFromRequestConfig(r RequestConfig, serverName string, caPool *x509.CertPool) (*RequestHTTPClient, error) {
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

func processHTTPRequestsByHost(r RequestConfig, caPool *x509.CertPool, isVerbose bool, debug bool) ([]ResponseData, error) {
func processHTTPRequestsByHost(r RequestConfig, caPool *x509.CertPool, isVerbose bool) ([]ResponseData, error) {
	var responseDataList []ResponseData

	requestBodyBytes := []byte(r.RequestBody)

	r.PrintTitle(isVerbose)

	for _, host := range r.Hosts {
		reqClient, err := NewHTTPClientFromRequestConfig(
			r,
			host.Name,
			caPool)
		if err != nil {
			return nil, err
		}

		urlList := getUrlsFromHost(host)

		for _, reqURL := range urlList {
			responseData := ResponseData{
				Request:          r,
				TransportAddress: reqClient.transportAddress,
				URL:              reqURL,
			}

			requestBodyReader := bytes.NewReader(requestBodyBytes)

			req, err := http.NewRequest(
				reqClient.method,
				reqURL,
				requestBodyReader,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create request: %w", err)
			}

			ua := httpUserAgent
			if len(r.UserAgent) > 0 {
				ua = r.UserAgent
			}

			req.Header.Add("User-Agent", ua)

			for _, header := range r.RequestHeaders {
				req.Header.Add(header.Key, header.Value)
			}

			r.PrintRequestDebug(req)

			resp, err := reqClient.client.Do(req)
			if err != nil {
				responseData.Error = err
				responseDataList = append(responseDataList, responseData)

				continue
			}

			r.PrintResponseDebug(resp)

			responseData.Response = resp

			if r.ResponseBodyMatchRegexp != emptyString || responseData.Request.PrintResponseBody {
				responseData.ImportResponseBody()
			}

			err = resp.Body.Close()
			if err != nil {
				fmt.Printf("unable to close response Body: %v\n", err)
			}

			responseDataList = append(responseDataList, responseData)
			responseData.PrintResponseData(isVerbose)
		}
	}

	return responseDataList, nil
}
