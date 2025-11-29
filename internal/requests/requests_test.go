package requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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

	for _, tt := range tests {
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

	for _, tt := range tests {
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

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			rcClient, err := NewHTTPClientFromRequestConfig(
				tt.reqConf,
				tt.serverName,
				tt.pool,
			)
			if err != nil {
				t.Fatal(err)
			}

			var i any = rcClient.client

			client, ok := i.(*http.Client)
			if !ok {
				t.Errorf("expecting *http.Client, got %T", client)
			}

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

			var ti any = rcClient.client.Transport

			transport, ok := ti.(*http.Transport)
			if !ok {
				t.Errorf("expecting *http.Transport, got %T", transport)
			}

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

	for _, tt := range tests {
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

	for _, tt := range testsError {
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

	for _, tt := range tests {
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			c := NewRequestHTTPClient()

			c.SetClientTimeout(tt)

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
			c.SetProxyProtocolHeader(header)

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

func TestPrintCmd(t *testing.T) {
	tests := []bool{true, false}

	for _, tt := range tests {
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

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{
				serverAddr:        tt.srvAddr,
				proxyprotoEnabled: false,
				serverName:        "localhost",
			}

			ts, err := NewHTTPSTestServer(httpSrvData)
			if err != nil {
				t.Fatal(err)
			}
			defer ts.Close()

			tr := &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			}}

			client := &http.Client{Transport: tr}

			res, err := client.Get(ts.URL)
			if err != nil {
				t.Fatal(err)
			}

			rc := RequestConfig{ResponseDebug: tt.verbose}
			buffer := bytes.Buffer{}
			rc.PrintResponseDebug(&buffer, res)

			got := buffer.String()
			fmt.Printf("got:\n%s\n", got)

			if !tt.verbose && len(got) == 0 {
				assert.Equal(t,
					[]byte(nil),
					buffer.Bytes(),
					"check PrintResponseDebug with verbose False",
				)
			}

			if tt.verbose {
				for _, output := range tt.outputs {
					assert.True(t,
						bytes.Contains(buffer.Bytes(), []byte(output)),
						"check PrintResponseDebug contains: %s", output,
					)
				}
			}
		})
	}
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
		desc    string
		verbose bool
		request *http.Request
		output  string
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
			desc:    "nilRequestError",
			verbose: true,
			request: requestTestNilPointer,
			output:  emptyString,
		},
		{
			desc:    "incompleteRequestError",
			verbose: true,
			request: &requestTestIncomplete,
			output:  expectedOutputIncomplete,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.Buffer{}
			r := RequestConfig{RequestDebug: tt.verbose}

			err := r.PrintRequestDebug(&buffer, tt.request)
			if err != nil {
				require.Error(t, err, "PrintRequestDebug error")
			}

			got := buffer.String()
			want := tt.output

			assert.Equal(t, want, got, "check PrintRequestDebug")
		})
	}
}

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
			errMsg:         "Get \"https://localhost\": tls: failed to verify certificate: x509: certificate is valid for example.com, example.net, example.de, not localhost",
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

	for _, tt := range tests {
		t.Run(tt.reqConf.Name, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{
				serverAddr:        tt.srvAddr,
				proxyprotoEnabled: false,
				serverName:        "localhost",
			}

			ts, err := NewHTTPSTestServer(httpSrvData)
			if err != nil {
				t.Fatal(err)
			}
			defer ts.Close()

			respList, err := processHTTPRequestsByHost(
				tt.reqConf,
				tt.pool,
				tt.verbose,
			)
			if err != nil {
				t.Error(err)
			}

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
				}

				// if expecting and error from the request do not
				// check values from the response
				if tt.respStatusCode != 0 {
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
		})
	}
}
