//nolint:revive
package requests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
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

// Host represents a target hostname and a list of URIs to request on that host.
type Host struct {
	Name    string `mapstructure:"name"`
	URIList []URI  `mapstructure:"uriList"`
}

// RequestHeader represents a single HTTP header key-value pair.
type RequestHeader struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

// RequestConfig defines the configuration for a single HTTP request set.
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

// RequestHTTPClient wraps an http.Client with additional configuration for requests.
type RequestHTTPClient struct {
	client             *http.Client
	method             string
	enableProxyProtoV2 bool
	transportAddress   string
}

// ResponseData holds the results and metadata of an executed HTTP request.
type ResponseData struct {
	Request                   RequestConfig
	TransportAddress          string
	URL                       string
	ResponseBody              string
	ResponseBodyRegexpMatched bool
	Response                  *http.Response
	Error                     error
}

// RequestsMetaConfig holds the global configuration and the list of requests to execute.
type RequestsMetaConfig struct {
	// TODO: can we remove the following
	// three lines and just embed an "options"
	// struct to take care of metadata?
	RequestDebug   bool
	RequestVerbose bool
	CACertsPool    *x509.CertPool
	Requests       []RequestConfig `mapstructure:"requests"`
}

// NewRequestsMetaConfig creates a new RequestsMetaConfig with the system's certificate pool.
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

// SetVerbose sets the verbosity level for the requests.
func (r *RequestsMetaConfig) SetVerbose(b bool) *RequestsMetaConfig {
	r.RequestVerbose = b
	return r
}

// SetDebug sets the debug level for the requests.
func (r *RequestsMetaConfig) SetDebug(b bool) *RequestsMetaConfig {
	r.RequestDebug = b
	return r
}

// SetCaPoolFromYAML loads a CA certificate pool from a PEM-encoded string.
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

// SetCaPoolFromFile loads a CA certificate pool from a PEM file.
func (r *RequestsMetaConfig) SetCaPoolFromFile(filePath string, fileReader certinfo.Reader) error {
	if filePath != "" {
		caCertsPool, err := certinfo.GetRootCertsFromFile(
			filePath,
			fileReader,
		)
		if err != nil {
			return err
		}

		r.CACertsPool = caCertsPool
	}

	return nil
}

// SetRequests sets the list of request configurations.
func (r *RequestsMetaConfig) SetRequests(requests []RequestConfig) *RequestsMetaConfig {
	r.Requests = requests
	return r
}

// PrintCmd prints a header for the requests execution if verbose mode is enabled.
func (r *RequestsMetaConfig) PrintCmd(w io.Writer) {
	if r.RequestVerbose {
		fmt.Fprintf(
			w,
			"\n%s\n",
			style.LgSprintf(style.Cmd, "Requests"),
		)
	}
}

// PrintTitle prints the request name and transport override information if verbose mode is enabled.
//
//nolint:revive
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

// PrintRequestDebug dumps the HTTP request to the provided writer if request debug is enabled.
func (r *RequestConfig) PrintRequestDebug(w io.Writer, req *http.Request) error {
	if req == nil {
		return errors.New("nil pointer to http.Request")
	}

	if r.RequestDebug {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Fprintf(w, "Warning: failed to dump request: %v\n", err)
			return err
		}

		_, err = fmt.Fprintf(w, "Requesting url: %s\nRequest dump:\n%s\n", req.URL, string(reqDump))

		return err
	}

	return nil
}

// PrintResponseDebug dumps the HTTP response and TLS information to the provided writer if response debug is enabled.
//
//nolint:revive
func (r *RequestConfig) PrintResponseDebug(w io.Writer, resp *http.Response) {
	// TODO: return an error
	if resp == nil {
		return
	}

	if r.ResponseDebug {
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			fmt.Fprintf(w, "Warning: failed to dump response: %v\n", err)
			return
		}

		fmt.Fprintf(w, "Requested url: %s\n", resp.Request.URL)
		fmt.Fprintf(w, "Response dump:\n%s\n", string(respDump))

		if resp.TLS != nil {
			fmt.Fprintln(w, "TLS:")
			fmt.Fprintf(w, "Version: %v\n", TLSVersionName(resp.TLS.Version))
			fmt.Fprintf(w, "CipherSuite: %v\n", cipherSuiteName(resp.TLS.CipherSuite))

			for i, cert := range resp.TLS.PeerCertificates {
				fmt.Fprintf(w, "Certificate %d:\n", i)
				certinfo.PrintCertInfo(cert, 1, w)
			}

			for i, chain := range resp.TLS.VerifiedChains {
				fmt.Fprintf(w, "Verified Chain %d:\n", i)

				for j, cert := range chain {
					fmt.Fprintf(w, " Cert %d:\n", j)
					certinfo.PrintCertInfo(cert, 2, w)
				}
			}
		} else {
			fmt.Fprintln(w, "TLS: Not available (non-TLS connection)")
		}
	}
}

// NewRequestHTTPClient creates a new RequestHTTPClient with default transport settings.
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

// SetServerName sets the ServerName for SNI in the TLS configuration.
func (rc *RequestHTTPClient) SetServerName(serverName string) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	if serverName == emptyString {
		return nil, errors.New("serverName cannot be empty")
	}

	if strings.Contains(serverName, "://") {
		return nil, fmt.Errorf("serverName should be a hostname, not a URL: %s", serverName)
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

// SetCACertsPool sets the CA certificate pool for the HTTP transport.
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

// SetInsecureSkipVerify sets whether to skip TLS certificate verification.
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

// SetMethod sets the HTTP method for the client.
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

// SetTransportOverride sets a dialer override to connect to a specific transport address.
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

// SetProxyProtocolV2 enables or disables PROXY protocol v2 support.
func (rc *RequestHTTPClient) SetProxyProtocolV2(enable bool) *RequestHTTPClient {
	rc.enableProxyProtoV2 = enable

	return rc
}

// SetProxyProtocolHeader sets a custom PROXY protocol header for the client's dialer.
func (rc *RequestHTTPClient) SetProxyProtocolHeader(header proxyproto.Header) (*RequestHTTPClient, error) {
	if rc.transportAddress == emptyString {
		return nil, errors.New("SetProxyProtocolHeader failed: transportOverrideURL not set")
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

// SetClientTimeout sets the timeout for the HTTP client in seconds.
func (rc *RequestHTTPClient) SetClientTimeout(timeout int) (*RequestHTTPClient, error) {
	if rc.client == nil {
		return nil, errors.New(
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize")
	}

	if timeout < 0 {
		return nil, fmt.Errorf("timeout value must be positive: %v provided", timeout)
	}

	t := time.Duration(timeout) * time.Second
	rc.client.Timeout = t

	return rc, nil
}

// NewHTTPClientFromRequestConfig initializes a RequestHTTPClient using the provided RequestConfig.
func NewHTTPClientFromRequestConfig(
	r RequestConfig,
	serverName string,
	caPool *x509.CertPool,
) (*RequestHTTPClient, error) {
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

	reqClient.SetProxyProtocolV2(r.EnableProxyProtocolV2)

	if r.EnableProxyProtocolV2 && r.TransportOverrideURL == emptyString {
		return nil, errors.New(
			"if EnableProxyProtocolV2 is true, a TransportOverrideURL must be set")
	}

	if r.EnableProxyProtocolV2 && reqClient.transportAddress != emptyString {
		header, err := proxyProtoHeaderFromRequest(r, serverName)
		if err != nil {
			return nil, fmt.Errorf("error creating proxyproto Header: %w", err)
		}

		_, err = reqClient.SetProxyProtocolHeader(header)
		if err != nil {
			return nil, fmt.Errorf("SetProxyProtocolHeader error: %w", err)
		}
	}

	return reqClient, nil
}

// processHTTPRequestsByHost executes the configured HTTP requests for all hosts and URIs.
//
//nolint:revive
func processHTTPRequestsByHost(
	r RequestConfig,
	caPool *x509.CertPool,
	isVerbose bool,
) ([]ResponseData, error) {
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

		urlList, err := getUrlsFromHost(host)
		if err != nil {
			return nil, err
		}

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

			if err := r.PrintRequestDebug(os.Stdout, req); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: PrintRequestDebug failed: %v\n", err)
			}

			resp, err := reqClient.client.Do(req)
			if err != nil {
				// if the request returns and error, we track it in
				// the responseData and stop processing.
				// Going further and importing the *http.Response into
				// ResponseData would result in a nil pointer error.
				// Avoiding that error will cost some duplicated code
				// in this branch mirroring the end of the outer one.
				responseData.Error = err
				responseDataList = append(responseDataList, responseData)
				responseData.PrintResponseData(isVerbose)

				continue
			}

			r.PrintResponseDebug(os.Stdout, resp)

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
