package certinfo

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		t.Parallel()

		cc, err := New()
		require.NoError(t, err)

		require.NotNil(t, cc.CACertsPool)
	})
}

var certinfoConfigFileReadErrorTests = []struct {
	desc        string
	caCertFile  string
	certFile    string
	keyFile     string
	reader      Reader
	expectError bool
	expectMsg   map[string]string
}{
	{
		desc:        "emptyString",
		caCertFile:  emptyString,
		certFile:    emptyString,
		keyFile:     emptyString,
		reader:      inputReader,
		expectError: false,
	},
	{
		desc:        "unreadableFile",
		caCertFile:  unreadableFile,
		certFile:    unreadableFile,
		keyFile:     unreadableFile,
		reader:      mockErrReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "failed to read CA bundle file: unable to read file testdata/unreadable-file.txt",
			"certs":  "error reading certificate file: unable to read file testdata/unreadable-file.txt",
			"key":    "unable to read file testdata/unreadable-file.txt",
		},
	},
	{
		desc:        "not exist",
		caCertFile:  "testdata/not-exist",
		certFile:    "testdata/not-exist",
		keyFile:     "testdata/not-exist",
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "failed to read CA bundle file: open testdata/not-exist: no such file or directory",
			"certs":  "error reading certificate file: open testdata/not-exist: no such file or directory",
			"key":    "open testdata/not-exist: no such file or directory",
		},
	},
	{
		desc:        "wrong file",
		caCertFile:  sampleTextFile,
		certFile:    sampleTextFile,
		keyFile:     sampleTextFile,
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "unable to create CertPool from file",
			"certs":  "no valid certificates found in file testdata/sample-text.txt",
			"key":    "failed to decode PEM",
		},
	},
	{
		desc: "wrong PEM encoded file",

		// PEM encoded keys get discarded by (_ *CertPool) AppendCertsFromPEM()
		// but do not trigger errors (ok == false)
		caCertFile:  RSASamplePKCS8PlaintextPrivateKey,
		certFile:    ECDSASamplePlaintextPrivateKey,
		keyFile:     ED25519SampleCertificate,
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "unable to create CertPool from file",
			"certs":  "no valid certificates found in file testdata/ecdsa-plaintext-private-key.pem",
			"key":    "unsupported key format or invalid password",
		},
	},
}

func TestCertinfo_SetCaPoolFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			err := cc.SetCaPoolFromFile(tt.caCertFile, tt.reader)

			// Config methods do nothing if an empty string is passed
			// as filePath
			if tt.caCertFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["caPool"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := New()
		require.NoError(t, errNew)

		err := cc.SetCaPoolFromFile(
			RSACaCertFile,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, RSACaCertFile, cc.CACertsFilePath)

		wantPool, errWantPool := GetRootCertsFromFile(
			RSACaCertFile,
			inputReader,
		)
		require.NoError(t, errWantPool)

		require.True(t, wantPool.Equal(cc.CACertsPool))

		if diff := cmp.Diff(wantPool, cc.CACertsPool); diff != "" {
			t.Errorf(
				"SetCaPoolFromFile: pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetCertsFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			err := cc.SetCertsFromFile(tt.certFile, tt.reader)

			// Config methods do nothing if an empty string is passed
			// as filePath
			if tt.certFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["certs"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := New()
		require.NoError(t, errNew)

		err := cc.SetCertsFromFile(
			RSASamplePKCS8Certificate,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, RSASamplePKCS8Certificate, cc.CertsBundleFilePath)

		wantCerts, errWantCrt := GetCertsFromBundle(
			RSASamplePKCS8Certificate,
			inputReader,
		)
		require.NoError(t, errWantCrt)

		if diff := cmp.Diff(wantCerts, cc.CertsBundle); diff != "" {
			t.Errorf(
				"SetCertsFromFile: pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetPrivateKeyFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			err := cc.SetPrivateKeyFromFile(
				tt.keyFile,
				privateKeyPwEnvVar,
				tt.reader,
			)

			// Config methods do nothing if an empty string is passed
			// as filePath
			if tt.keyFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["key"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := New()
		require.NoError(t, errNew)

		err := cc.SetPrivateKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
			privateKeyPwEnvVar,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, ED25519SamplePlaintextPrivateKey, cc.PrivKeyFilePath)

		wantKey, errKey := GetKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
			privateKeyPwEnvVar,
			inputReader,
		)
		require.NoError(t, errKey)

		if diff := cmp.Diff(wantKey, cc.PrivKey); diff != "" {
			t.Errorf(
				"SetPrivateKeyFromFile: key mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetTLSInsecure(t *testing.T) {
	tests := []bool{
		true,
		false,
	}

	for _, tc := range tests {
		tt := tc
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			cc.SetTLSInsecure(tt)

			require.Equal(
				t,
				tt,
				cc.TLSInsecure,
			)
		})
	}
}

func TestCertinfo_SetTLSServerName(t *testing.T) {
	tests := []string{
		emptyString,
		"test",
		"example.com",
	}

	for _, tc := range tests {
		tt := tc
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			cc.SetTLSServerName(tt)

			require.Equal(
				t,
				tt,
				cc.TLSServerName,
			)
		})
	}
}

//nolint:revive
func TestCertinfo_SetTLSEndpoint(t *testing.T) {
	tests := []struct {
		desc           string
		endpoint       string
		expectEndpoint string
		expectHost     string
		expectPort     string
		processErr     bool
		expectMsg      string
	}{
		{
			desc:           "success",
			endpoint:       "localhost:443",
			expectEndpoint: "localhost:443",
			expectHost:     "localhost",
			expectPort:     "443",
		},
		{
			desc:           "success IPV6",
			endpoint:       "[::1]:443",
			expectEndpoint: "[::1]:443",
			expectHost:     "::1",
			expectPort:     "443",
		},
		{
			desc:           "success IPV4",
			endpoint:       "127.0.0.1:443",
			expectEndpoint: "127.0.0.1:443",
			expectHost:     "127.0.0.1",
			expectPort:     "443",
		},
		{
			desc:     "error malformed host",
			endpoint: "localh#$%ost:443",
			//nolint:revive
			processErr: true,
			expectMsg:  "unable to get endpoint certificates: TLS handshake failed",
		},
		{
			desc:       "error missing port",
			endpoint:   "localhost",
			processErr: true,
			expectMsg:  "invalid TLS endpoint \"localhost\": address localhost: missing port in address",
		},
		{
			desc: "error missing host",
			//nolint:revive
			endpoint:   ":80443",
			processErr: true,
			expectMsg:  "unable to get endpoint certificates: TLS handshake failed: dial tcp: address 80443: invalid port",
		},
		{
			//nolint:revive
			desc:       "error endpoint includes scheme",
			endpoint:   "https://localhost:80443",
			processErr: true,
			expectMsg:  "invalid TLS endpoint \"https://localhost:80443\": address https://localhost:80443: too many colons in address",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := New()
			require.NoError(t, errNew)

			err := cc.SetTLSEndpoint(tt.endpoint)

			if !tt.processErr {
				// skip requiring NoError since SetTLSEndpoint will always return network errors
				// in this case. See tests related to GetRemoteCerts for more

				// require.NoError(t, err)
				require.Equal(t, tt.expectEndpoint, cc.TLSEndpoint, "check TLSEndpoint")
				require.Equal(t, tt.expectHost, cc.TLSEndpointHost, "check TLSEndpointHost")
				require.Equal(t, tt.expectPort, cc.TLSEndpointPort, "check TLSEndpointPort")

				return
			}

			require.ErrorContains(t, err, tt.expectMsg)
		})
	}
}

func TestCertinfo_ProbeTLSInfo(t *testing.T) {
	// Start a local TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse host and port from server URL
	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	cc, err := New()
	require.NoError(t, err)

	cc.SetTLSInfoRequested(true)
	require.True(t, cc.TLSInfoRequested)

	// Skip verification to allow connection to the self-signed test server
	cc.SetTLSInsecure(true)
	cc.SetTLSServerName("example.com")

	err = cc.SetTLSEndpoint(u.Host)
	require.NoError(t, err)

	err = cc.ProbeTLSInfo()
	require.NoError(t, err)

	// Since it's a local TLS server run by Go's httptest, it supports TLS 1.3 or TLS 1.2
	hasSupported := false

	for _, supported := range cc.ProbedProtocols {
		if supported {
			hasSupported = true

			break
		}
	}

	require.True(t, hasSupported)
	require.NotEmpty(t, cc.ProbedCiphers)
}

func TestCertinfo_ProbeTLSInfo_NotRequested(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.SetTLSInfoRequested(false)
	require.False(t, cc.TLSInfoRequested)

	err = cc.ProbeTLSInfo()
	require.NoError(t, err)
	require.Empty(t, cc.NegotiatedProtocol)
}

func TestCertinfo_ProbeTLSInfo_NoEndpoint(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.SetTLSInfoRequested(true)

	err = cc.ProbeTLSInfo()
	require.NoError(t, err)
	require.Empty(t, cc.ProbedProtocols)
}

func TestCertinfo_ProbeTLSInfo_Unreachable(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.SetTLSInfoRequested(true)
	cc.SetTLSInsecure(true)

	// Manually populate fields to bypass pre-flight certificate fetch in SetTLSEndpoint
	cc.TLSEndpoint = "127.0.0.1:54321"
	cc.TLSEndpointHost = "127.0.0.1"
	cc.TLSEndpointPort = "54321"

	err = cc.ProbeTLSInfo()
	require.NoError(t, err)

	// When unreachable, all scanned protocols should be unsupported
	for _, supported := range cc.ProbedProtocols {
		require.False(t, supported)
	}
}

func TestCertinfo_GettersAndSetters(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.NegotiatedProtocol = "TLS 1.3"
	require.Equal(t, "TLS 1.3", cc.NegotiatedProtocol)

	cc.NegotiatedCipher = "TLS_AES_128_GCM_SHA256"
	require.Equal(t, "TLS_AES_128_GCM_SHA256", cc.NegotiatedCipher)
}

func TestCertinfo_PrintTLSInfo_NotRequested(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.TLSInfoRequested = false

	var buf bytes.Buffer

	ks := lipgloss.NewStyle()
	sl := lipgloss.NewStyle()
	sv := lipgloss.NewStyle()

	cc.printTLSInfo(&buf, ks, sl, sv)
	require.Empty(t, buf.String())
}

func TestCertinfo_PrintTLSInfo_HappyPath(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.TLSInfoRequested = true
	cc.NegotiatedProtocol = "TLS 1.3"
	cc.NegotiatedCipher = "TLS_AES_128_GCM_SHA256"
	cc.ProbedProtocols = map[string]bool{
		"TLS 1.3": true,
		"TLS 1.2": true,
		"TLS 1.1": false,
		"TLS 1.0": false,
	}
	cc.ProbedCiphers = []ProbedCipher{
		{
			Name:      "TLS_AES_128_GCM_SHA256",
			Protocol:  "TLS 1.3",
			Supported: true,
			Insecure:  false,
		},
		{
			Name:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			Protocol:  "TLS 1.2",
			Supported: true,
			Insecure:  true,
		},
	}

	var buf bytes.Buffer

	ks := lipgloss.NewStyle()
	sl := lipgloss.NewStyle()
	sv := lipgloss.NewStyle()

	cc.printTLSInfo(&buf, ks, sl, sv)

	got := buf.String()
	require.Contains(t, got, "Negotiated TLS Connection")
	require.Contains(t, got, "TLS 1.3")
	require.Contains(t, got, "TLS_AES_128_GCM_SHA256")
	require.Contains(t, got, "Protocol Support Scan")
	require.Contains(t, got, "Cipher Suite Scan")
	require.Contains(t, got, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
	require.Contains(t, got, "Insecure")
	require.Contains(t, got, "Secure")
}

func TestCertinfo_PrintTLSInfo_NoSupportedCiphers(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.TLSInfoRequested = true
	cc.NegotiatedProtocol = "TLS 1.2"
	cc.NegotiatedCipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	cc.ProbedProtocols = map[string]bool{
		"TLS 1.3": false,
		"TLS 1.2": true,
		"TLS 1.1": false,
		"TLS 1.0": false,
	}
	cc.ProbedCiphers = []ProbedCipher{
		{
			Name:      "TLS_AES_128_GCM_SHA256",
			Protocol:  "TLS 1.3",
			Supported: false,
			Insecure:  false,
		},
	}

	var buf bytes.Buffer

	ks := lipgloss.NewStyle()
	sl := lipgloss.NewStyle()
	sv := lipgloss.NewStyle()

	cc.printTLSInfo(&buf, ks, sl, sv)

	got := buf.String()
	require.Contains(t, got, "Negotiated TLS Connection")
	require.Contains(t, got, "No supported cipher suites found")
}

func TestCertinfo_TLSVersionToString_Unknown(t *testing.T) {
	t.Parallel()

	res := tlsVersionToString(0x1234)
	require.Equal(t, "Unknown (0x1234)", res)
}

func TestCertinfo_ProbeTLSInfo_SingleCipher(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.TLSInfoRequested = true
	cc.TLSEndpoint = "127.0.0.1:54321"
	cc.TLSEndpointHost = "127.0.0.1"
	cc.TLSEndpointPort = "54321"

	// Mock only 1 cipher suite to trigger numWorkers > numJobs inside probeCiphersConcurrently
	ciphers := []*tls.CipherSuite{
		{
			ID:       tls.TLS_AES_128_GCM_SHA256,
			Name:     "TLS_AES_128_GCM_SHA256",
			Insecure: false,
		},
	}

	res := cc.probeCiphersConcurrently(ciphers)
	require.Len(t, res, 1)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", res[0].Name)
	require.False(t, res[0].Supported)
}

func TestCertinfo_PrintData_WithTLSInfo(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)

	cc.TLSInfoRequested = true
	cc.NegotiatedProtocol = "TLS 1.3"
	cc.NegotiatedCipher = "TLS_AES_128_GCM_SHA256"

	var buf bytes.Buffer

	err = cc.PrintData(&buf)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "Negotiated TLS Connection")
}
