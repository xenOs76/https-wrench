package requests

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequestsMetaConfig(t *testing.T) {
	t.Run("NewRequestsMetaConfig", func(t *testing.T) {
		t.Parallel()

		rmc, err := NewRequestsMetaConfig()
		if err != nil {
			require.Error(t, err, "error when calling NewRequestsMetaConfig()")
		}

		assert.NoError(t, err)

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

	for _, tt := range tests {
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

	for _, tt := range tests {
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

	for _, tt := range tests {
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

	for _, tt := range tests {
		testname := fmt.Sprintf("SetCaPoolFromFile(%v)", tt.desc)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			rmc, _ := NewRequestsMetaConfig()
			err := rmc.SetCaPoolFromFile(tt.certFile)
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

func TestNewRequestHTTPClient_SetServerName(t *testing.T) {
	tests := []string{
		"", "localhost", "127.0.0.1", "[::1]", "example.com", " a silly string ",
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()
			c.SetServerName(tt)

			// Extract the transport via type assertion
			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
			}

			if transport.TLSClientConfig == nil {
				t.Fatal("TLSClientConfig is nil")
			}

			if transport.TLSClientConfig.ServerName != tt {
				t.Errorf("expected ServerName to be %s, got %s",
					tt, transport.TLSClientConfig.ServerName)
			}
		})
	}
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

	for _, tt := range tests {
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

func TestNewRequestHTTPClient_SetInsecureSkipVerify_struct(t *testing.T) {
	tests := []bool{true, false}
	for _, tt := range tests {
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
	for _, tt := range tests {
		testname := fmt.Sprintf("%v", tt)

		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)
			}
		})
	}
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

	for _, tt := range tests {
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

	for _, tt := range tests {
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

// Test SetTransportOverride method for RequestHTTPClient.
// Use case: we want our client to redirect HTTPS request meant for https://hostname to a
// third party proxy. This in order to test the settings of that proxy before pointing to it the DNS
// record of hostname.
// We pass the URL of the proxy via SetTrasportOverride to a new RequestHTTPClient.
// That will update the scruct setting the value of transportAddr and the Transport of the
// http.client.
// Once the TLS server is started on an address other than https://hostname, we expect the
// client to contact the TLS server even if it is requested to connect to https://servername.
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

	for _, tt := range tests {
		testname := fmt.Sprintf("%v", tt.trasportURL)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			_, _ = c.SetTransportOverride(tt.trasportURL)
			if c.transportAddress != tt.transportAddr {
				t.Errorf("expected %s, got %s", tt.transportAddr, tt.trasportURL)
			}

			fmt.Printf("c.transportAddress is %s\n", c.transportAddress)

			httpSrvData := demoHttpServerData{serverAddr: tt.transportAddr}

			ts, err := NewHTTPSTestServer(httpSrvData)
			if err != nil {
				t.Fatal(err)
			}
			defer ts.Close()

			// WARN: the following check does not pass, but:
			// 		expected: "localhost:6455"
			// 		actual  : "127.0.0.1:6455"
			//
			// fmt.Printf("Server Addr is %s\n", ts.Config.Addr)
			// assert.Equal(t, tt.transportAddr, ts.Listener.Addr().String())

			// Extract the transport via type assertion
			tr, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", tr)
			}

			tr.TLSClientConfig = &tls.Config{
				RootCAs: caCertPool,
				// InsecureSkipVerify: true,
			}
			testClient := &http.Client{Transport: tr}

			clientURL := "https://" + tt.requestHost

			// req, err := testClient.Get(clientURL)
			req, err := http.NewRequest("GET", clientURL, nil)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			fmt.Println(ts.URL)

			uaString := "TestSetTrasportOverride"
			req.Header.Set("User-Agent", uaString)

			// res, err := testClient.Get(clientURL)
			res, err := testClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			//
			// fmt.Printf("Resp StatusCode was: %v\n", res.StatusCode)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			//
			// fmt.Printf("Req URL was: %v\n", res.Request.URL)
			assert.Equal(t, res.Request.URL.Scheme+"://"+res.Request.URL.Host,
				"https://"+tt.requestHost)
			//
			// fmt.Printf("User Agent was: %v\n",
			// 	res.Request.Header.Values("user-agent"))
			assert.Equal(t, []string{uaString},
				res.Request.Header.Values("User-Agent"))

			printResponseBody(res)
		})
	}
}

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

	for _, tt := range tests {
		t.Run(tt.testname, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{
				serverAddr:        tt.addr,
				proxyprotoEnabled: true,
			}

			ts, err := NewHTTPSTestServer(httpSrvData)
			if err != nil {
				t.Fatal(err)
			}

			defer ts.Close()

			// fmt.Println(tt.testname)
			// fmt.Print("Client URL: ")
			// fmt.Println(ts.URL)
			// fmt.Print("Listener address: ")
			// fmt.Println(ts.Listener.Addr())
			//
			transportURL := "https://" + tt.addr
			reqURL := "https://" + tt.serverName

			reqConf := RequestConfig{
				EnableProxyProtocolV2: true,
				TransportOverrideURL:  transportURL,
			}

			header, err := proxyProtoHeaderFromRequest(reqConf, tt.serverName)
			if err != nil {
				t.Fatal(err)
			}

			c := NewRequestHTTPClient()
			c.SetTransportOverride(transportURL)
			c.SetProxyProtocolV2(header)

			// Extract the transport via type assertion
			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
			}

			transport.TLSClientConfig = &tls.Config{
				RootCAs: caCertPool,
				// InsecureSkipVerify: true,
			}

			testClient := &http.Client{Transport: transport}

			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			uaString := "TestSetProxyProtocolV2"
			req.Header.Set("User-Agent", uaString)

			res, err := testClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			// fmt.Printf("Resp StatusCode was: %v\n", res.StatusCode)
			assert.Equal(t, http.StatusOK, res.StatusCode)

			// fmt.Printf("Req URL was: %v\n", res.Request.URL)
			assert.Equal(t, res.Request.URL.Scheme+"://"+res.Request.URL.Host,
				reqURL)

			// fmt.Printf("User Agent was: %v\n",
			// 	res.Request.Header.Values("user-agent"))
			assert.Equal(t, []string{uaString},
				res.Request.Header.Values("User-Agent"))

			printResponseBody(res)
		})
	}
}
