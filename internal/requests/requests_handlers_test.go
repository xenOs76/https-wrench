package requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseHeader_Print(t *testing.T) {
	tests := []struct {
		header ResponseHeader
		str    string
	}{
		{
			header: "testString",
			str:    "testString",
		},
	}

	for i, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("TestString%v", i)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.str, tt.header.String())
		})
	}
}

func TestURI_Parse(t *testing.T) {
	tests := []struct {
		uri         URI
		expectValid bool
	}{
		{uri: "testString", expectValid: false},
		{uri: "/validUri", expectValid: true},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("TestURI_%s", tt.uri)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			if tt.expectValid {
				assert.True(t, tt.uri.Parse())
			}

			if !tt.expectValid {
				assert.False(t, tt.uri.Parse())
			}
		})
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		inputVal    uint16
		expectedStr string
	}{
		{
			inputVal:    tls.VersionSSL30,
			expectedStr: "SSL 3.0",
		},
		{
			inputVal:    tls.VersionTLS10,
			expectedStr: "TLS 1.0",
		},
		{
			inputVal:    tls.VersionTLS11,
			expectedStr: "TLS 1.1",
		},
		{
			inputVal:    tls.VersionTLS12,
			expectedStr: "TLS 1.2",
		},
		{
			inputVal:    tls.VersionTLS13,
			expectedStr: "TLS 1.3",
		},
		{
			inputVal:    0x0399,
			expectedStr: "Unknown (0x399)",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		// testname := fmt.Sprintf("%s", tt.expectedStr)
		t.Run(tt.expectedStr, func(t *testing.T) {
			t.Parallel()

			version := TLSVersionName(tt.inputVal)

			assert.Contains(t, version, tt.expectedStr)
		})
	}
}

func TestCipherSuiteName(t *testing.T) {
	tests := []struct {
		inputVal    uint16
		expectedStr string
	}{
		{
			inputVal:    0xcca9,
			expectedStr: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		},

		{
			inputVal:    0x1303,
			expectedStr: "TLS_CHACHA20_POLY1305_SHA256",
		},

		{
			inputVal:    0xc023,
			expectedStr: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		},

		{
			inputVal:    0x9999,
			expectedStr: "Unknown (0x9999)",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("Test_%s", tt.expectedStr)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			name := cipherSuiteName(tt.inputVal)

			assert.Equal(t, tt.expectedStr, name)
		})
	}
}

func TestFilterResponseHeaders(t *testing.T) {
	sampleHTTPHeader := http.Header{
		"Content-Type":  []string{"application/json"},
		"Server":        []string{"nginx"},
		"Cache-Control": []string{"max-age=3600"},
	}

	sampleHTTPHeader2 := http.Header{
		"Server":     []string{"Envoy"},
		"User-Agent": []string{"go-test"},
	}

	tests := []struct {
		inputHeader      http.Header
		filter           []string
		expectedOutput   []string
		unexpectedOutput []string
	}{
		{
			inputHeader:    sampleHTTPHeader,
			filter:         []string{"Server"},
			expectedOutput: []string{"nginx", "Server"},
			unexpectedOutput: []string{
				"application/json",
				"Content-Type", "Cache-Control", "max-age",
			},
		},
		{
			inputHeader:      sampleHTTPHeader2,
			filter:           []string{"User-Agent"},
			expectedOutput:   []string{"User-Agent", "go-test"},
			unexpectedOutput: []string{"Envoy", "Server"},
		},
		{
			inputHeader:      sampleHTTPHeader2,
			filter:           []string{},
			expectedOutput:   []string{"go-test", "Envoy"},
			unexpectedOutput: []string{"NotInMap"},
		},
	}

	for i, tc := range tests {
		tt := tc // safer when using t.Parallel()
		testname := fmt.Sprintf("Test_%v", i)
		t.Run(testname, func(t *testing.T) {
			// t.Parallel() // WARN the test fails if t.Parallel()
			output := filterResponseHeaders(tt.inputHeader, tt.filter)

			for _, o := range tt.expectedOutput {
				assert.Contains(t, output, o)
			}

			for _, uo := range tt.unexpectedOutput {
				require.NotContains(t, output, uo)
			}
		})
	}
}

func TestGetUrlsFromHost(t *testing.T) {
	tests := []struct {
		desc           string
		inputHost      Host
		expectedOutput []string
		expectedError  bool
	}{
		{
			desc:      "AllValid",
			inputHost: Host{Name: "localhost", URIList: []URI{"/one", "/two", "/three"}},
			expectedOutput: []string{
				"https://localhost/one",
				"https://localhost/two",
				"https://localhost/three",
			},
		},
		{
			desc:      "OneNotParsing",
			inputHost: Host{Name: "localhost", URIList: []URI{"one", "/two", "/three"}},
			expectedOutput: []string{
				"https://localhost/two",
				"https://localhost/three",
			},
			expectedError: true,
		},
		{
			desc:      "NoURIList",
			inputHost: Host{Name: "example.com"},
			expectedOutput: []string{
				"https://example.com",
			},
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			output, err := getUrlsFromHost(tt.inputHost)

			if tt.expectedError {
				require.Error(t, err)
			}

			if !tt.expectedError {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedOutput, output)
			}
		})
	}
}

func TestTransportAddressFromURLString(t *testing.T) {
	tests := []struct {
		desc         string
		input        string
		expectError  bool
		expectOutput string
	}{
		{
			desc:         "NoPort",
			input:        "https://localhost",
			expectError:  false,
			expectOutput: "localhost:443",
		},

		{
			desc:         "Valid",
			input:        "https://example.com:8443",
			expectError:  false,
			expectOutput: "example.com:8443",
		},

		{
			desc:         "NoScheme",
			input:        "example.com:8443",
			expectError:  false,
			expectOutput: "example.com:8443",
		},

		{
			desc:         "EmptyInput",
			input:        emptyString,
			expectError:  true,
			expectOutput: "empty string provided as transportURL",
		},

		{
			desc:         "Invalid",
			input:        "loca$%^lhost",
			expectError:  true,
			expectOutput: "parse \"https://loca$%^lhost\": invalid URL escape \"%^l\"",
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			output, err := transportAddressFromURLString(tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, tt.expectOutput, err.Error())
			}

			if !tt.expectError {
				require.NoError(t, err)
				assert.Equal(t, tt.expectOutput, output)
			}
		})
	}
}

func TestRenderTLSData(t *testing.T) {
	tests := []struct {
		srvAddr           string
		srvTLSCipherSuite uint16
		srvTLSMaxVersion  uint16
		reqConf           RequestConfig
		pool              *x509.CertPool
		injectTLSError    bool
	}{
		// WARN: not all cipher suites listed as 'TLS 1.0 - 1.2 cipher suites'
		// are supported.
		// Ref:
		// https://pkg.go.dev/crypto/tls#pkg-constants
		// https://github.com/golang/go/issues/53750
		{
			srvAddr:           "localhost:46101",
			srvTLSCipherSuite: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			srvTLSMaxVersion:  tls.VersionTLS12,
			reqConf: RequestConfig{
				Name:                 "example.com",
				TransportOverrideURL: "https://localhost:46101",
				Hosts: []Host{
					{Name: "example.com"},
				},
			},
			pool: caCertPool,
		},

		// WARN: I was expecting a cipherSuite list of one element as input to the server conf
		// would make only that one available.
		// This test seems to prove the default list is returned instead (..SHA256 vs ...SHA384)
		// Is this related to the certificate?
		{
			srvAddr: "localhost:46102",
			// srvTLSCipherSuite: tls.TLS_AES_256_GCM_SHA384,
			srvTLSCipherSuite: tls.TLS_AES_128_GCM_SHA256,
			srvTLSMaxVersion:  tls.VersionTLS13,
			reqConf: RequestConfig{
				Name:                 "example.net",
				TransportOverrideURL: "https://localhost:46102",
				Hosts: []Host{
					{Name: "example.net"},
				},
			},
			pool: caCertPool,
		},
		{
			srvAddr:           "localhost:46103",
			srvTLSCipherSuite: tls.TLS_AES_128_GCM_SHA256,
			srvTLSMaxVersion:  tls.VersionTLS13,
			reqConf: RequestConfig{
				Name:                 "example.de",
				TransportOverrideURL: "https://localhost:46103",
				Hosts: []Host{
					{Name: "example.de"},
				},
			},
			pool:           caCertPool,
			injectTLSError: true,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.reqConf.Name, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{
				serverAddr:        tt.srvAddr,
				tlsCipherSuites:   []uint16{tt.srvTLSCipherSuite},
				tlsMaxVersion:     tt.srvTLSMaxVersion,
				proxyprotoEnabled: false,
				serverName:        "localhost",
			}

			ts, err := NewHTTPSTestServer(httpSrvData)
			require.NoError(t, err)

			defer ts.Close()

			respList, err := processHTTPRequestsByHost(
				tt.reqConf,
				tt.pool,
				false,
			)
			require.NoError(t, err)

			for _, r := range respList {
				buffer := bytes.Buffer{}

				if tt.injectTLSError {
					r.Response.TLS = nil
				}

				RenderTLSData(&buffer, r.Response)
				got := buffer.String()

				if tt.injectTLSError {
					assert.Contains(t, got, "No TLS connection state available")
					break
				}

				assert.Contains(t, got, "TLS:")
				assert.Contains(t, got, "Version")

				expectedTLSVersion := tls.VersionName(tt.srvTLSMaxVersion)
				assert.Contains(t, got, expectedTLSVersion)

				assert.Contains(t, got, "CipherSuite")

				expectedCipherSuiteName := tls.CipherSuiteName(tt.srvTLSCipherSuite)
				assert.Contains(t, got, expectedCipherSuiteName)

				assert.Contains(t, got, "Certificate 0")
				assert.Contains(t, got, "Subject")
				assert.Contains(t, got, "DNSNames")
				assert.Contains(t, got, "Issuer")
				assert.Contains(t, got, tt.reqConf.Hosts[0].Name)
			}
		})
	}
}

func TestHandleRequests(t *testing.T) {
	reqMeta1 := RequestsMetaConfig{
		CACertsPool:    caCertPool,
		RequestVerbose: true,
		Requests: []RequestConfig{
			{
				Name:                 "Meta10",
				TransportOverrideURL: "localhost:46201",
				UserAgent:            "Meta10",
				Hosts: []Host{
					{Name: "example.com"},
				},
			},
		},
	}

	reqMeta2 := RequestsMetaConfig{
		CACertsPool:    caCertPool,
		RequestVerbose: true,
		Requests: []RequestConfig{
			{
				Name:                 "Meta11",
				TransportOverrideURL: "localhost:46202",
				UserAgent:            "Meta11",
				Hosts: []Host{
					{Name: emptyString},
				},
			},
		},
	}

	tests := []struct {
		desc      string
		srvAddr   string
		reqMeta   RequestsMetaConfig
		expectErr bool
	}{
		{
			desc:    "Meta10",
			srvAddr: "localhost:46201",
			reqMeta: reqMeta1,
		},
		{
			desc:      "Meta11",
			srvAddr:   "localhost:46202",
			reqMeta:   reqMeta2,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		tt := tc // safer when using t.Parallel()
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{
				serverAddr: tt.srvAddr,
				serverName: "localhost",
			}

			ts, err := NewHTTPSTestServer(httpSrvData)
			require.NoError(t, err)

			defer ts.Close()

			buffer := bytes.Buffer{}
			respMap, err := HandleRequests(&buffer, &tt.reqMeta)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			out := buffer.String()
			assert.Contains(t, out, "Requests")

			for reqConfName, rdList := range respMap {
				for _, rd := range rdList {
					gotReqConfName := rd.Request.Name

					assert.Equal(t, gotReqConfName, reqConfName)

					ua := tt.reqMeta.Requests[0].UserAgent
					wantUa := httpUserAgent

					if ua != wantUa {
						wantUa = ua
					}

					gotUa := rd.Response.Request.UserAgent()
					assert.Equal(t, wantUa, gotUa)
				}
			}
		})
	}
}
