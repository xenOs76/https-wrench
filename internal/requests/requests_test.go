package requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/certinfo"
)

func TestNewRequestsMetaConfig(t *testing.T) {
	t.Run("NewRequestsMetaConfig", func(t *testing.T) {
		t.Parallel()

		rmc, err := NewRequestsMetaConfig()
		require.NoError(t, err)

		var i any = rmc

		_, ok := i.(*RequestsMetaConfig)
		assert.True(t, ok, "rmc should of type *RequestsMetaConfig")
		assert.False(t, rmc.RequestDebug, "RequestDebug default value")
		assert.False(t, rmc.RequestVerbose, "RequestVerbose default value")

		var emptyRequests []RequestConfig
		assert.Equal(t, emptyRequests,
			rmc.Requests, "Requests default value")

		var p any = rmc.CACertsPool

		_, ok = p.(*x509.CertPool)
		assert.True(t, ok, "CACertsPool should of type *x509.CertPool")

		if diff := cmp.Diff(systemCertPool, rmc.CACertsPool); diff != "" {
			t.Errorf("CACertsPool vs systemCertPool mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestRequestsMetaConfig_SetVerbose(t *testing.T) {
	tests := []bool{true, false}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("SetVerbose(%v)", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			rmc, _ := NewRequestsMetaConfig()
			rmc.SetVerbose(tt)
			assert.Equal(t, tt, rmc.RequestVerbose)
		})
	}
}

func TestRequestsMetaConfig_SetDebug(t *testing.T) {
	tests := []bool{true, false}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("SetDebug(%v)", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			rmc, _ := NewRequestsMetaConfig()
			rmc.SetDebug(tt)
			assert.Equal(t, tt, rmc.RequestDebug)
		})
	}
}

func TestRequestsMetaConfig_SetCaPoolFromYAML(t *testing.T) {
	tests := []struct {
		desc       string
		certString string
		certPool   *x509.CertPool
	}{
		{
			"demoCaCert",
			caCertPEMString,
			caCertPool,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("SetCaPoolFromYAML(%v)", tt.desc)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			rmc, _ := NewRequestsMetaConfig()
			err := rmc.SetCaPoolFromYAML(tt.certString)
			require.NoError(t, err)

			var pool any = rmc.CACertsPool

			_, ok := pool.(*x509.CertPool)
			assert.True(t, ok, "CACertsPool should be of type *x509.CertPool")

			if diff := cmp.Diff(tt.certPool, rmc.CACertsPool); diff != "" {
				t.Errorf("CACertsPool mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRequestsMetaConfig_SetCaPoolFromFile(t *testing.T) {
	tempDir = t.TempDir()
	fmt.Printf("Created tempDir: %s\n", tempDir)

	tempCACertFile, err := createTmpFileWithContent(tempDir,
		"caCertFile", []byte(caCertPEMString))
	if err != nil {
		t.Error(err)
	}

	tests := []struct {
		desc       string
		certString string
		certPool   *x509.CertPool
		certFile   string
	}{
		{
			"demoCaCert",
			caCertPEMString,
			caCertPool,
			tempCACertFile,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("SetCaPoolFromFile(%v)", tt.desc)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			var fr certinfo.InputReader

			rmc, _ := NewRequestsMetaConfig()
			err := rmc.SetCaPoolFromFile(tt.certFile, fr)
			require.NoError(t, err)

			var pool any = rmc.CACertsPool

			_, ok := pool.(*x509.CertPool)
			assert.True(t, ok, "CACertsPool should be of type *x509.CertPool")

			if diff := cmp.Diff(tt.certPool, rmc.CACertsPool); diff != "" {
				t.Errorf("CACertsPool mismatch (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("SetCaPoolFromFile_Error", func(t *testing.T) {
		t.Parallel()

		rmc, _ := NewRequestsMetaConfig()
		err := rmc.SetCaPoolFromFile("non_existent_file.pem", nil)
		require.Error(t, err)
	})
}

func TestRequestsMetaConfig_SetCaPoolFromYAML_Error(t *testing.T) {
	t.Run("SetCaPoolFromYAML_Error", func(t *testing.T) {
		t.Parallel()

		rmc, _ := NewRequestsMetaConfig()
		err := rmc.SetCaPoolFromYAML("invalid cert data")
		require.Error(t, err)
		require.ErrorContains(t, err, "unable to create CA Certs Pool from YAML")
	})
}

func TestRequestsMetaConfig_SetRequests(t *testing.T) {
	hosts := []Host{
		{Name: "www.example.com"},
		{Name: "example.com", URIList: []URI{"/test", "test2"}},
	}

	requestConfigs := []RequestConfig{
		{
			Name:                 "first request",
			Insecure:             true,
			TransportOverrideURL: "localhost:443",
		},
		{
			Name:                 "second request",
			PrintResponseBody:    true,
			TransportOverrideURL: "localhost:443",
			Hosts:                hosts,
		},
	}

	tests := [][]RequestConfig{requestConfigs}

	for _, tc := range tests {
		tt := tc // use a local copy of tc should be safer when using t.Parallel()
		testname := fmt.Sprintf("SetRequests(%v)", tt[0].Name)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			rmc, err := NewRequestsMetaConfig()
			require.NoError(t, err)
			rmc.SetRequests(tt)

			if diff := cmp.Diff(tt, rmc.Requests); diff != "" {
				t.Errorf("Requests mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewRequestHTTPClient(t *testing.T) {
	t.Run("NewRequestHTTPClient", func(t *testing.T) {
		t.Parallel()

		client := NewRequestHTTPClient()

		var i any = client

		_, ok := i.(*RequestHTTPClient)
		assert.True(t, ok, "client should be of type *RequestHTTPClient")
		transport, ok := client.client.Transport.(*http.Transport)
		assert.True(t, ok,
			"client.Transport should be of type *http.Transport")
		assert.NotNil(t,
			transport,
			"transport should not be nil")
		assert.True(t,
			transport.ForceAttemptHTTP2,
			"ForceAttemptHTTP2 should be true")
		assert.Equal(t,
			transportMaxIdleConns,
			transport.MaxIdleConns,
			"unexpected value for transportMaxIdleConns")
		assert.Equal(t,
			transportIdleConnTimeout,
			transport.IdleConnTimeout,
			"unexpected value for IdleConnTimeout")
		assert.Equal(t,
			transportTLSHandshakeTimeout,
			transport.TLSHandshakeTimeout,
			"unexpected value for TLSHandshakeTimeout")
		assert.Equal(t,
			transportResponseHeaderTimeout,
			transport.ResponseHeaderTimeout,
			"unexpected value for ResponseHeaderTimeout")
		assert.Equal(t,
			transportExpectContinueTimeout,
			transport.ExpectContinueTimeout,
			"unexpected value for ExpectContinueTimeout")
	})
}

func TestNewHTTPClientFromRequestConfig_Error(t *testing.T) {
	tests := []struct {
		desc       string
		reqConf    RequestConfig
		serverName string
		errMsg     string
	}{
		{
			desc: "EnableProxyProtocolV2",
			reqConf: RequestConfig{
				EnableProxyProtocolV2: true,
			},
			serverName: "localhost",
			errMsg:     "if EnableProxyProtocolV2 is true, a TransportOverrideURL must be set",
		},
		{
			desc: "EnableProxyProtoNoServerName",
			reqConf: RequestConfig{
				TransportOverrideURL:  "https://localhost:8443",
				EnableProxyProtocolV2: true,
			},
			serverName: emptyString,
			errMsg:     "SetServerName error: serverName cannot be empty",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			_, err := NewHTTPClientFromRequestConfig(
				tt.reqConf,
				tt.serverName,
				nil,
			)
			require.Error(t, err)
			assert.Equal(t,
				tt.errMsg,
				err.Error(),
			)
		})
	}
}

func TestNewHTTPClientFromRequestConfig_SubErrors(t *testing.T) {
	tests := []struct {
		desc       string
		reqConf    RequestConfig
		serverName string
		errMsg     string
	}{
		{
			desc: "SetClientTimeout error",
			reqConf: RequestConfig{
				ClientTimeout: -1,
			},
			serverName: "localhost",
			errMsg:     "SetClientTimeout error: timeout value must be positive: -1 provided",
		},
		{
			desc: "SetMethod error",
			reqConf: RequestConfig{
				RequestMethod: "INVALID",
			},
			serverName: "localhost",
			errMsg:     "SetMethod error: INVALID: HTTP method not found",
		},
		{
			desc: "SetTransportOverride error",
			reqConf: RequestConfig{
				TransportOverrideURL: "https://loca$%^lhost",
			},
			serverName: "localhost",
			errMsg:     "SetTransportOverride error: failed to parse transport override url: https://loca$%^lhost",
		},
		{
			desc: "proxyProtoHeaderFromRequest error",
			reqConf: RequestConfig{
				EnableProxyProtocolV2: true,
				TransportOverrideURL:  "https://test.invalid:443",
			},
			serverName: "localhost",
			errMsg: "error creating proxyproto Header: failed to resolve transport override hostname's IPs': " +
				"lookup test.invalid", // we'll just check ErrorContains
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			_, err := NewHTTPClientFromRequestConfig(
				tt.reqConf,
				tt.serverName,
				nil,
			)
			require.Error(t, err)
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

//nolint:revive
func TestNewHTTPClientFromRequestConfig(t *testing.T) {
	tests := []struct {
		desc             string
		reqConf          RequestConfig
		serverName       string
		pool             *x509.CertPool
		transportAddress string
	}{
		{
			desc: "transpAddr",
			reqConf: RequestConfig{
				ClientTimeout:        3,
				UserAgent:            "test1-ua",
				TransportOverrideURL: "https://localhost:45555",
				Insecure:             true,
				RequestMethod:        http.MethodGet,
			},
			serverName:       "localhost",
			transportAddress: "localhost:45555",
		},
		{
			desc: "proxyProto",
			reqConf: RequestConfig{
				TransportOverrideURL:  "https://localhost:8443",
				RequestMethod:         http.MethodHead,
				EnableProxyProtocolV2: true,
			},
			serverName:       "localhost",
			transportAddress: "localhost:8443",
		},
		{
			desc: "caPool",
			reqConf: RequestConfig{
				RequestMethod: http.MethodPut,
			},
			serverName: "localhost",
			pool:       caCertPool,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			runNewHTTPClientFromRequestConfigSubtest(t, tt)
		})
	}
}

func TestNewRequestHTTPClient_SetServerName(t *testing.T) {
	tests := []string{
		"[::1]",
		"localhost",
		"127.0.0.1",
		"example.com",
		" a silly string ",
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			_, err := c.SetServerName(tt)
			if err != nil {
				t.Fatal(err)
			}

			// Extract the transport via type assertion
			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
			}

			assert.NotNil(t,
				transport.TLSClientConfig,
				"check TLSClientConfig not nil",
			)

			assert.Equal(t,
				tt,
				transport.TLSClientConfig.ServerName,
				"check ServerName in TLSClientConfig",
			)
		})
	}
}

func TestNewRequestHTTPClient_SetServerName_clientError(t *testing.T) {
	t.Run("malformedClient", func(t *testing.T) {
		t.Parallel()

		noTransportClient := http.Client{}
		c := NewRequestHTTPClient()

		c.client = &noTransportClient

		_, err := c.SetServerName("localhost")

		require.Error(t, err)
	})
}

func TestNewRequestHTTPClient_SetServerName_Error(t *testing.T) {
	testsError := []struct {
		desc       string
		serverName string
		errMsg     string
	}{
		{
			"empty serverName",
			emptyString,
			"serverName cannot be empty",
		},
		{
			"url as serverName",
			"https://localhost",
			"serverName should be a hostname, not a URL: https://localhost",
		},
	}

	for _, tc := range testsError {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()
			_, err := c.SetServerName(tt.serverName)
			require.Error(t, err)
			assert.Equal(t, tt.errMsg, err.Error())
		})
	}

	t.Run("Error: Nil HTTP client", func(t *testing.T) {
		t.Parallel()

		var c RequestHTTPClient

		_, err := c.SetServerName("localhost")
		require.Error(t, err)
		assert.Equal(t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})
}

func TestNewRequestHTTPClient_SetClientTimeout(t *testing.T) {
	tests := []int{
		3, 0, 50,
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			_, err := c.SetClientTimeout(tt)
			require.NoError(t, err)

			var i any = c.client.Timeout

			duration, ok := i.(time.Duration)
			if !ok {
				t.Fatalf("expected time.Duration, got %T", c.client.Timeout)
			}

			assert.Equal(t, time.Duration(tt)*time.Second, duration)
		})
	}
}

func TestNewRequestHTTPClient_SetClientTimeout_Error(t *testing.T) {
	t.Run("Negative Timeout", func(t *testing.T) {
		t.Parallel()

		c := NewRequestHTTPClient()
		timeout := -1

		_, err := c.SetClientTimeout(timeout)
		require.Error(t, err)
		assert.Equal(t, "timeout value must be positive: -1 provided", err.Error())
	})

	t.Run("Nil Timeout", func(t *testing.T) {
		t.Parallel()

		var c RequestHTTPClient

		timeout := 10

		_, err := c.SetClientTimeout(timeout)
		require.Error(t, err)
		assert.Equal(
			t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})
}

func TestNewRequestHTTPClient_SetCaCertsPool(t *testing.T) {
	var emptyPool *x509.CertPool

	defaultCertPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal("unable to create x509 SystemCertPool")
	}

	tests := []struct {
		testname string
		gotPool  *x509.CertPool
		wantPool *x509.CertPool
	}{
		{"empty Pool", emptyPool, defaultCertPool},
		{"System Cert Pool", defaultCertPool, defaultCertPool},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()
			c.SetCACertsPool(tt.gotPool)

			// Extract the transport via type assertion
			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
			}

			if transport.TLSClientConfig == nil {
				t.Fatal("TLSClientConfig is nil")
			}

			if diff := cmp.Diff(tt.wantPool, transport.TLSClientConfig.RootCAs); diff != "" {
				t.Errorf("RootCAs value mismatch for %v (-want +got):\n%s", tt.testname, diff)
			}
		})
	}
}

func TestNewRequestHTTPClient_SetCaCertsPool_Error(t *testing.T) {
	t.Run("nilClient", func(t *testing.T) {
		t.Parallel()

		var c RequestHTTPClient

		_, err := c.SetCACertsPool(caCertPool)

		require.Error(t, err)
		assert.Equal(t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})

	t.Run("malformedClient", func(t *testing.T) {
		t.Parallel()

		incompleteClient := http.Client{}
		c := NewRequestHTTPClient()

		c.client = &incompleteClient

		_, err := c.SetCACertsPool(caCertPool)

		require.Error(t, err)

		assert.Equal(t,
			"expected *http.Transport, got <nil>",
			err.Error(),
		)
	})
}

func TestNewRequestHTTPClient_SetInsecureSkipVerify_struct(t *testing.T) {
	tests := []bool{true, false}
	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt)

		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()
			c.SetInsecureSkipVerify(tt)

			// Extract the transport via type assertion
			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
			}

			if transport.TLSClientConfig == nil {
				t.Fatal("TLSClientConfig is nil")
			}

			if transport.TLSClientConfig.InsecureSkipVerify != tt {
				t.Errorf("expected InsecureSkipVerify=%v, got %v",
					tt, transport.TLSClientConfig.InsecureSkipVerify)
			}
		})
	}
}

func TestNewRequestHTTPClient_SetInsecureSkipVerify_tlsServer(t *testing.T) {
	tests := []bool{true, false}
	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt)

		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			}))
			defer ts.Close()

			c := NewRequestHTTPClient()
			c.SetInsecureSkipVerify(tt)

			testClient := &http.Client{Transport: c.client.Transport}

			res, err := testClient.Get(ts.URL)
			if !tt {
				require.Error(t, err)
			}

			if tt {
				require.NoError(t, err)

				defer res.Body.Close()

				assert.Equal(t, http.StatusOK, res.StatusCode)
			}
		})
	}
}

func TestNewRequestHTTPClient_SetInsecureSkipVerify_Error(t *testing.T) {
	t.Run("nilClient", func(t *testing.T) {
		t.Parallel()

		var c RequestHTTPClient

		_, err := c.SetInsecureSkipVerify(true)

		require.Error(t, err)
		assert.Equal(t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})

	t.Run("malformedClient", func(t *testing.T) {
		t.Parallel()

		incompleteClient := http.Client{}
		c := NewRequestHTTPClient()

		c.client = &incompleteClient

		_, err := c.SetInsecureSkipVerify(true)

		require.Error(t, err)

		assert.Equal(t,
			"expected *http.Transport, got <nil>",
			err.Error(),
		)
	})
}

func TestNewRequestHTTPClient_SetMethod(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{http.MethodGet, http.MethodGet},
		{http.MethodHead, http.MethodHead},
		{http.MethodPost, http.MethodPost},
		{http.MethodPut, http.MethodPut},
		{http.MethodPatch, http.MethodPatch},
		{http.MethodDelete, http.MethodDelete},
		{http.MethodConnect, http.MethodConnect},
		{http.MethodOptions, http.MethodOptions},
		{http.MethodTrace, http.MethodTrace},
		{"", httpClientDefaultMethod},
		{"NotExist", emptyString},
		{"post", http.MethodPost},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt.got)

		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			_, _ = c.SetMethod(tt.got)
			if c.method != tt.want {
				t.Errorf("expected %s, got %s", tt.want, c.method)
			}
		})
	}
}

func TestRequestHTTPClient_SetTransportOverride_transportAddress_struc(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{emptyString, emptyString},
		{"https://localhost:8443", "localhost:8443"},
		{"https://example.com", "example.com:443"},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt.got)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			_, _ = c.SetTransportOverride(tt.got)
			if c.transportAddress != tt.want {
				t.Errorf("expected %s, got %s", tt.want, tt.got)
			}
		})
	}
}

func TestRequestHTTPClient_SetTransportOverride_Error(t *testing.T) {
	t.Run("nilClient", func(t *testing.T) {
		t.Parallel()

		var c RequestHTTPClient

		_, err := c.SetTransportOverride("http://localhost")
		require.Error(t, err)
		assert.Equal(t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})

	t.Run("malformedClient", func(t *testing.T) {
		t.Parallel()

		incompleteClient := http.Client{}
		c := NewRequestHTTPClient()

		c.client = &incompleteClient

		_, err := c.SetTransportOverride("http://localhost")

		require.Error(t, err)

		assert.Equal(t,
			"expected *http.Transport, got <nil>",
			err.Error(),
		)
	})
}

// Test SetTransportOverride method for RequestHTTPClient.
// Use case: we want our client to redirect HTTPS request meant for https://hostname to a
// third party proxy. This in order to test the settings of that proxy before pointing to it the DNS
// record of hostname.
// We pass the URL of the proxy via SetTrasportOverride to a new RequestHTTPClient.
// That will update the scruct setting the value of transportAddr and the Transport of the
// http.client.
// Once the TLS server is started on an address other than https://hostname, we expect the
// client to contact the TLS server even if it is requested to connect to https://servername.
//
//nolint:revive // test function
func TestRequestHTTPClient_SetTransportOverride_transportAddress_server(t *testing.T) {
	tests := []struct {
		trasportURL   string
		transportAddr string
		requestHost   string
	}{
		{
			"https://127.0.0.1:6455",
			"127.0.0.1:6455",
			"example.com",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt.trasportURL)
		t.Run(testname, func(t *testing.T) {
			runSetTransportOverrideSubtest(t, tt)
		})
	}
}

//nolint:revive // test function
func TestRequestHTTPClient_SetProxyProtocolV2_server(t *testing.T) {
	tests := []struct {
		testname   string
		addr       string
		serverName string
	}{
		{
			"localhost IPv4",
			"127.0.0.1:45678",
			"example.net",
		},
		{
			"localhost IPv6",
			"[::1]:45679",
			"example.de",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.testname, func(t *testing.T) {
			runSetProxyProtocolV2Subtest(t, tt)
		})
	}
}

func TestRequestHTTPClient_SetProxyProtocolHeader_Error(t *testing.T) {
	t.Run("nilClient", func(t *testing.T) {
		t.Parallel()

		c := RequestHTTPClient{transportAddress: "127.0.0.1:443"}
		header := proxyproto.Header{}
		_, err := c.SetProxyProtocolHeader(header)

		require.Error(t, err)
		assert.Equal(t,
			"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
			err.Error(),
		)
	})

	t.Run("malformedClient", func(t *testing.T) {
		t.Parallel()

		incompleteClient := http.Client{}
		c := NewRequestHTTPClient()
		c.transportAddress = "127.0.0.1:443"
		c.client = &incompleteClient

		header := proxyproto.Header{}
		_, err := c.SetProxyProtocolHeader(header)
		require.Error(t, err)

		assert.Equal(t,
			"expected *http.Transport, got <nil>",
			err.Error(),
		)
	})

	t.Run("noTransportAddress", func(t *testing.T) {
		t.Parallel()

		incompleteClient := http.Client{}
		c := NewRequestHTTPClient()
		c.client = &incompleteClient

		header := proxyproto.Header{}
		_, err := c.SetProxyProtocolHeader(header)
		require.Error(t, err)

		assert.Equal(t,
			"SetProxyProtocolHeader failed: transportOverrideURL not set",
			err.Error(),
		)
	})
}

func TestPrintCmd(t *testing.T) {
	tests := []bool{true, false}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.Buffer{}
			r := RequestsMetaConfig{RequestVerbose: tt}
			r.PrintCmd(&buffer)

			got := buffer.String()
			if tt {
				assert.Contains(t, got,
					"Requests",
					"check PrintCmd when verbose",
				)
			} else {
				assert.Empty(t,
					got,
					"check empty outputs from PrintCmd when not verbose",
				)
			}
		})
	}
}

//nolint:revive
func TestPrintResponseDebug(t *testing.T) {
	tests := []struct {
		desc    string
		srvAddr string
		verbose bool
		outputs []string
	}{
		{
			desc:    "verboseTrue",
			srvAddr: "localhost:46010",
			verbose: true,
			outputs: []string{
				"Requested url:",
				"Response dump:",
				"DemoHTTPSServer Handler - client output",
				"TLS:",
				"CipherSuite:",
			},
		},
		{
			desc:    "verboseFalse",
			srvAddr: "localhost:46011",
			verbose: false,
			outputs: []string{emptyString},
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			runPrintResponseDebugSubtest(t, tt)
		})
	}
}

func TestPrintResponseDebug_Error(t *testing.T) {
	t.Run("NilResponse", func(t *testing.T) {
		rc := RequestConfig{ResponseDebug: true}
		buffer := bytes.Buffer{}
		rc.PrintResponseDebug(&buffer, nil)

		got := buffer.String()
		assert.Empty(t,
			got,
			"output should be empty when Response is nil",
		)
	})
}

func TestPrintResponseDebug_nonTLS(t *testing.T) {
	t.Run("non-TLS", func(t *testing.T) {
		respURL := url.URL{Scheme: "http", Host: "localhost"}
		req := http.Request{URL: &respURL}
		resp := http.Response{
			StatusCode: 200,
			Request:    &req,
		}
		rc := RequestConfig{ResponseDebug: true}
		buffer := bytes.Buffer{}
		rc.PrintResponseDebug(&buffer, &resp)

		assert.True(t,
			bytes.Contains(buffer.Bytes(), []byte("TLS: Not available")),
			"check non-TLS connection",
		)
	})
}

//nolint:revive
func TestPrintRequestDebug(t *testing.T) {
	httpTestHeader := http.Header{}
	httpTestHeader.Add("user-agent", "go-test")
	requestTest := http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "localhost"},
		Header: httpTestHeader,
	}

	requestTestIncomplete := http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "localhost"},
	}

	var requestTestNilPointer *http.Request

	expectedOutput := "Requesting url: https://localhost\nRequest dump:\nGET / "
	expectedOutput += "HTTP/1.1\r\nHost: localhost\r\nUser-Agent: go-test\r\nAccept-Encoding: "
	expectedOutput += "gzip\r\n\r\n\n"

	expectedOutputIncomplete := "Warning: failed to dump request: http: nil Request.Header\n"

	tests := []struct {
		desc      string
		verbose   bool
		request   *http.Request
		output    string
		expectErr bool
	}{
		{
			desc:    "verboseTrue",
			verbose: true,
			request: &requestTest,
			output:  expectedOutput,
		},

		{
			desc:    "verboseFalse",
			verbose: false,
			request: &requestTest,
			output:  emptyString,
		},
		{
			desc:      "nilRequestError",
			verbose:   true,
			request:   requestTestNilPointer,
			output:    emptyString,
			expectErr: true,
		},
		{
			desc:      "incompleteRequestError",
			verbose:   true,
			request:   &requestTestIncomplete,
			output:    expectedOutputIncomplete,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.Buffer{}
			r := RequestConfig{RequestDebug: tt.verbose}

			err := r.PrintRequestDebug(&buffer, tt.request)

			if tt.expectErr {
				require.Error(t, err, "PrintRequestDebug should return an error")
			} else {
				require.NoError(t, err, "PrintRequestDebug should not return an error")
			}

			got := buffer.String()
			want := tt.output

			assert.Equal(t, want, got, "check PrintRequestDebug")
		})
	}
}

//nolint:revive
func TestProcessHTTPRequestsByHost(t *testing.T) {
	tests := []struct {
		srvAddr        string
		reqConf        RequestConfig
		pool           *x509.CertPool
		verbose        bool
		respStatusCode int
		errMsg         string
	}{
		{
			srvAddr: "localhost:46001",
			reqConf: RequestConfig{
				Name:                 "StatusOK",
				TransportOverrideURL: "https://localhost:46001",
				UserAgent:            "test-ua",
				RequestHeaders: []RequestHeader{
					{Key: "testKey", Value: "testValue"},
					{Key: "testKey2", Value: "testValue2"},
				},
				Hosts: []Host{
					{Name: "example.com"},
				},
			},
			pool:           caCertPool,
			verbose:        false,
			respStatusCode: http.StatusOK,
		},

		{
			srvAddr: "localhost:46002",
			reqConf: RequestConfig{
				Name:                 "invalidServerName",
				TransportOverrideURL: "https://localhost:46002",
				Hosts: []Host{
					{Name: "localhost"},
				},
			},
			pool:           caCertPool,
			verbose:        false,
			respStatusCode: 0,
			errMsg: "Get \"https://localhost\": tls: failed to verify certificate: " +
				"x509: certificate is valid for example.com, example.net, example.de, not localhost",
		},

		{
			srvAddr: "localhost:46003",
			reqConf: RequestConfig{
				Name:                    "bodyRex",
				ResponseBodyMatchRegexp: "DemoHTTPSServer Handler - client output",
				PrintResponseBody:       true,
				TransportOverrideURL:    "https://localhost:46003",
				Hosts: []Host{
					{Name: "example.com"},
				},
			},
			pool:           caCertPool,
			verbose:        true,
			respStatusCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.reqConf.Name, func(t *testing.T) {
			runProcessHTTPRequestsByHostSubtest(t, tt)
		})
	}
}

func TestRequestHTTPClient_DialContextErrors(t *testing.T) {
	t.Run("SetTransportOverride DialContext Error", func(t *testing.T) {
		t.Parallel()

		reqConf := RequestConfig{
			TransportOverrideURL: "https://localhost:11111", // dead port
		}

		client, err := NewHTTPClientFromRequestConfig(reqConf, "localhost", nil)
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "https://localhost", nil)
		_, err = client.client.Do(req)
		require.Error(t, err)
	})

	t.Run("SetProxyProtocolV2 DialContext Error", func(t *testing.T) {
		t.Parallel()

		reqConf := RequestConfig{
			EnableProxyProtocolV2: true,
			TransportOverrideURL:  "https://localhost:11111", // dead port
		}

		client, err := NewHTTPClientFromRequestConfig(reqConf, "localhost", nil)
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "https://localhost", nil)
		_, err = client.client.Do(req)
		require.Error(t, err)
	})
}

func TestProcessHTTPRequestsByHost_Errors(t *testing.T) {
	t.Run("getUrlsFromHost error", func(t *testing.T) {
		reqConf := RequestConfig{
			Hosts: []Host{
				{Name: "localhost", URIList: []URI{"invalid"}},
			},
		}
		_, err := processHTTPRequestsByHost(reqConf, nil, false)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid uri")
	})
}

func TestProxyProtoHeaderFromRequest_Errors(t *testing.T) {
	t.Run("not enabled", func(t *testing.T) {
		_, err := proxyProtoHeaderFromRequest(RequestConfig{}, "localhost")
		require.ErrorContains(t, err, "proxy protocol v2 is not enabled")
	})

	// url.Parse won't fail for typical invalid URLs, but let's try a control character
	t.Run("serverName parse fail", func(t *testing.T) {
		_, err := proxyProtoHeaderFromRequest(RequestConfig{EnableProxyProtocolV2: true}, string([]byte{0x7f}))
		require.Error(t, err)
	})

	t.Run("transportOverride parse fail", func(t *testing.T) {
		_, err := proxyProtoHeaderFromRequest(RequestConfig{
			EnableProxyProtocolV2: true,
			TransportOverrideURL:  string([]byte{0x7f}),
		}, "localhost")
		require.Error(t, err)
	})
}

type mockErrReader struct{}

func (mockErrReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("mock read error")
}

func TestImportResponseBody_Errors(t *testing.T) {
	t.Run("already imported", func(t *testing.T) {
		rd := ResponseData{ResponseBody: "already imported"}
		rd.ImportResponseBody() // should return immediately
		require.Equal(t, "already imported", rd.ResponseBody)
	})

	t.Run("read error", func(t *testing.T) {
		rd := ResponseData{
			Response: &http.Response{
				Body: io.NopCloser(mockErrReader{}),
			},
		}
		rd.ImportResponseBody() // should print error and return
		require.Empty(t, rd.ResponseBody)
	})

	t.Run("bad regexp", func(t *testing.T) {
		rd := ResponseData{
			Request: RequestConfig{ResponseBodyMatchRegexp: "["},
			Response: &http.Response{
				Header: make(http.Header),
				Body:   io.NopCloser(bytes.NewBufferString("test body")),
			},
		}
		rd.ImportResponseBody()
		require.False(t, rd.ResponseBodyRegexpMatched)
		require.Equal(t, "test body", rd.ResponseBody)
	})

	t.Run("html content type highlighting", func(t *testing.T) {
		rd := ResponseData{
			Response: &http.Response{
				Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:   io.NopCloser(bytes.NewBufferString("<html><body>hello</body></html>")),
			},
		}
		rd.ImportResponseBody()
		require.Contains(t, rd.ResponseBody, "hello")
	})
}

type newHTTPClientFromRequestConfigTestCase struct {
	desc             string
	reqConf          RequestConfig
	serverName       string
	pool             *x509.CertPool
	transportAddress string
}

func runNewHTTPClientFromRequestConfigSubtest(t *testing.T, tt newHTTPClientFromRequestConfigTestCase) {
	t.Parallel()

	rcClient, err := NewHTTPClientFromRequestConfig(
		tt.reqConf,
		tt.serverName,
		tt.pool,
	)
	require.NoError(t, err)

	client := rcClient.client

	assert.Equal(t,
		time.Duration(tt.reqConf.ClientTimeout)*time.Second,
		client.Timeout,
		"check client Timeout",
	)

	assert.Equal(t,
		tt.reqConf.RequestMethod,
		rcClient.method,
		"check client Method",
	)

	assert.Equal(t,
		tt.reqConf.EnableProxyProtocolV2,
		rcClient.enableProxyProtoV2,
		"check proxy proto enabled",
	)

	if tt.transportAddress != emptyString {
		assert.Equal(t,
			tt.transportAddress,
			rcClient.transportAddress,
			"check transportAddress",
		)
	}

	transport, ok := rcClient.client.Transport.(*http.Transport)
	require.True(t, ok, "expecting *http.Transport, got %T", rcClient.client.Transport)

	assert.Equal(t,
		tt.reqConf.Insecure,
		transport.TLSClientConfig.InsecureSkipVerify,
		"check Insecure",
	)

	currPool := systemCertPool
	if tt.pool != nil {
		currPool = caCertPool
	}

	if diff := cmp.Diff(currPool, transport.TLSClientConfig.RootCAs); diff != "" {
		t.Errorf("Client CA Pool mismatch (-want +got):\n%s", diff)
	}
}

type setTransportOverrideTestCase struct {
	trasportURL   string
	transportAddr string
	requestHost   string
}

func runSetTransportOverrideSubtest(t *testing.T, tt setTransportOverrideTestCase) {
	t.Parallel()

	c := NewRequestHTTPClient()

	_, err := c.SetTransportOverride(tt.trasportURL)
	require.NoError(t, err)

	assert.Equal(t, tt.transportAddr, c.transportAddress)

	fmt.Printf("c.transportAddress is %s\n", c.transportAddress)

	httpSrvData := demoHttpServerData{serverAddr: tt.transportAddr}

	ts, err := NewHTTPSTestServer(httpSrvData)
	require.NoError(t, err)

	defer ts.Close()

	// Extract the transport via type assertion
	tr, ok := c.client.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", c.client.Transport)

	tr.TLSClientConfig = &tls.Config{
		RootCAs: caCertPool,
	}
	testClient := &http.Client{Transport: tr}

	clientURL := "https://" + tt.requestHost

	req, err := http.NewRequest("GET", clientURL, nil)
	require.NoError(t, err)

	fmt.Println(ts.URL)

	uaString := "TestSetTrasportOverride"
	req.Header.Set("User-Agent", uaString)

	res, err := testClient.Do(req)
	require.NoError(t, err)

	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, res.Request.URL.Scheme+"://"+res.Request.URL.Host,
		"https://"+tt.requestHost)
	assert.Equal(t, []string{uaString},
		res.Request.Header.Values("User-Agent"))

	printResponseBody(res)
}

type setProxyProtocolV2TestCase struct {
	testname   string
	addr       string
	serverName string
}

func runSetProxyProtocolV2Subtest(t *testing.T, tt setProxyProtocolV2TestCase) {
	t.Parallel()

	httpSrvData := demoHttpServerData{
		serverAddr:        tt.addr,
		proxyprotoEnabled: true,
	}

	ts, err := NewHTTPSTestServer(httpSrvData)
	require.NoError(t, err)

	defer ts.Close()

	transportURL := "https://" + tt.addr
	reqURL := "https://" + tt.serverName

	reqConf := RequestConfig{
		EnableProxyProtocolV2: true,
		TransportOverrideURL:  transportURL,
	}

	header, err := proxyProtoHeaderFromRequest(reqConf, tt.serverName)
	require.NoError(t, err)

	c := NewRequestHTTPClient()
	_, err = c.SetTransportOverride(transportURL)
	require.NoError(t, err)

	_, err = c.SetProxyProtocolHeader(header)
	require.NoError(t, err)

	// Extract the transport via type assertion
	transport, ok := c.client.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", c.client.Transport)

	transport.TLSClientConfig = &tls.Config{
		RootCAs: caCertPool,
	}

	testClient := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", reqURL, nil)
	require.NoError(t, err)

	uaString := "TestSetProxyProtocolV2"
	req.Header.Set("User-Agent", uaString)

	res, err := testClient.Do(req)
	require.NoError(t, err)

	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, res.Request.URL.Scheme+"://"+res.Request.URL.Host,
		reqURL)
	assert.Equal(t, []string{uaString},
		res.Request.Header.Values("User-Agent"))
}

type printResponseDebugTestCase struct {
	desc    string
	srvAddr string
	verbose bool
	outputs []string
}

func runPrintResponseDebugSubtest(t *testing.T, tt printResponseDebugTestCase) {
	t.Parallel()

	httpSrvData := demoHttpServerData{
		serverAddr:        tt.srvAddr,
		proxyprotoEnabled: false,
		serverName:        "localhost",
	}

	ts, err := NewHTTPSTestServer(httpSrvData)
	require.NoError(t, err)

	defer ts.Close()

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: caCertPool,
	}}

	client := &http.Client{Transport: tr}

	res, err := client.Get(ts.URL)
	require.NoError(t, err)

	defer res.Body.Close()

	rc := RequestConfig{ResponseDebug: tt.verbose}
	buffer := bytes.Buffer{}
	rc.PrintResponseDebug(&buffer, res)

	got := buffer.String()
	fmt.Printf("got:\n%s\n", got)

	if !tt.verbose {
		assert.Empty(t, got, "check PrintResponseDebug with verbose False")
		return
	}

	for _, output := range tt.outputs {
		assert.Contains(t, got, output, "check PrintResponseDebug contains: %s", output)
	}
}

type processHTTPRequestsByHostTestCase struct {
	srvAddr        string
	reqConf        RequestConfig
	pool           *x509.CertPool
	verbose        bool
	respStatusCode int
	errMsg         string
}

func runProcessHTTPRequestsByHostSubtest(t *testing.T, tt processHTTPRequestsByHostTestCase) {
	// t.Parallel()
	httpSrvData := demoHttpServerData{
		serverAddr:        tt.srvAddr,
		proxyprotoEnabled: false,
		serverName:        "localhost",
	}

	ts, err := NewHTTPSTestServer(httpSrvData)
	require.NoError(t, err)

	defer ts.Close()

	respList, err := processHTTPRequestsByHost(
		tt.reqConf,
		tt.pool,
		tt.verbose,
	)
	if err != nil {
		t.Error(err)
	}

	verifyProcessHTTPRequestsResults(t, tt, respList)
}

func verifyProcessHTTPRequestsResults(t *testing.T, tt processHTTPRequestsByHostTestCase, respList []ResponseData) {
	t.Helper()

	for _, r := range respList {
		fmt.Printf("resp type: %T\n", r)

		assert.Equal(t,
			tt.srvAddr,
			r.TransportAddress,
			"check TransportAddress",
		)

		if tt.respStatusCode == 0 {
			assert.Equal(t,
				tt.errMsg,
				r.Error.Error(),
				"check Response Error",
			)

			continue
		}

		// if expecting and error from the request do not
		// check values from the response
		require.NoError(t,
			r.Error,
			"check NoError in ResponseData",
		)

		ua := httpUserAgent
		if tt.reqConf.UserAgent != emptyString {
			ua = tt.reqConf.UserAgent
		}

		assert.Equal(t,
			ua,
			r.Response.Request.Header.Get("user-agent"),
			"check UserAgent",
		)

		assert.Equal(t,
			len(tt.reqConf.ResponseBodyMatchRegexp) > 0,
			r.ResponseBodyRegexpMatched,
			"check body rex match",
		)

		assert.Equal(t,
			tt.respStatusCode,
			r.Response.StatusCode,
			"check StatusCode",
		)

		for _, headers := range tt.reqConf.RequestHeaders {
			assert.Equal(t,
				headers.Value,
				r.Response.Request.Header.Get(headers.Key),
				"check RequestHeaders Key",
			)
		}
	}
}
