package certinfo

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/tlstest"
)

//nolint:revive
func TestCertinfo_GetRemoteCerts(t *testing.T) {
	tests := []struct {
		desc        string
		srvCfg      tlstest.ServerConfig
		serverName  string
		caCertFile  string
		insecure    bool
		expectError bool
		expectMsg   string
		wantCurveID string
	}{
		{
			desc: "RSA Cert Success",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertBundleFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			caCertFile: RSACaCertFile,
		},
		{
			desc: "Error Secure and No CA Cert",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			caCertFile: emptyString,
			//nolint:revive
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},

		{
			desc: "Malformed Server Certificate",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASamplePKCS8Certificate,
				ServerKeyFile:  RSASamplePKCS8PlaintextPrivateKey,
			},
			serverName: "example.com",
			caCertFile: RSACaCertFile,
			//nolint:revive
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate relies on legacy Common Name field, use SANs instead",
		},
		{
			desc: "No CA Cert and Insecure",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			insecure:   true,
			caCertFile: emptyString,
		},
		{
			desc: "Wrong CA Cert and Secure",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			caCertFile: RSASamplePKCS8Certificate,
			//nolint:revive
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
		{
			desc: "Wrong CA Cert and Insecure",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			caCertFile: RSASamplePKCS8Certificate,
			insecure:   true,
		},
		{
			desc: "IPV6 Endpoint RSA Cert Success",
			srvCfg: tlstest.ServerConfig{
				ListenHost:     "::1",
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
			serverName: "example.com",
			caCertFile: RSACaCertFile,
		},
		{
			desc: "Error wrong ServerName",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				//nolint:revive
				ServerKeyFile: RSASampleCertKeyFile,
			},
			serverName:  "example.co.uk",
			caCertFile:  RSACaCertFile,
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate is valid for example.com, example.net, example.de, not example.co.uk",
		},
		{
			desc: "X25519MLKEM768 key exchange",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile:      RSASampleCertBundleFile,
				ServerKeyFile:       RSASampleCertKeyFile,
				TLSCurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			},
			serverName:  "example.com",
			caCertFile:  RSACaCertFile,
			wantCurveID: "X25519MLKEM768",
		},
		{
			desc: "SecP256r1MLKEM768 key exchange",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile:      RSASampleCertBundleFile,
				ServerKeyFile:       RSASampleCertKeyFile,
				TLSCurvePreferences: []tls.CurveID{tls.SecP256r1MLKEM768},
			},
			serverName:  "example.com",
			caCertFile:  RSACaCertFile,
			wantCurveID: "SecP256r1MLKEM768",
		},
		{
			desc: "SecP384r1MLKEM1024 key exchange",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile:      RSASampleCertBundleFile,
				ServerKeyFile:       RSASampleCertKeyFile,
				TLSCurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024},
			},
			serverName:  "example.com",
			caCertFile:  RSACaCertFile,
			wantCurveID: "SecP384r1MLKEM1024",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			ts, err := tlstest.NewServer(tt.srvCfg)
			require.NoError(t, err)
			t.Cleanup(ts.Close)

			endpoint := ts.Listener.Addr().String()
			host, port, err := net.SplitHostPort(endpoint)
			require.NoError(t, err)

			cc, err := New()
			require.NoError(t, err)

			cc.SetTLSServerName(tt.serverName)
			cc.SetCaPoolFromFile(tt.caCertFile, inputReader)
			cc.SetTLSInsecure(tt.insecure)
			cc.SetTLSEndpoint(t.Context(), endpoint)

			err = cc.GetRemoteCerts(t.Context())
			if !tt.expectError {
				require.NoError(t, err, "check error not expected")
				require.Equal(t, tt.serverName, cc.TLSServerName, "check TLSServerName")
				require.Equal(t, host, cc.TLSEndpointHost, "check TLSEndpointHost")
				require.Equal(t, port, cc.TLSEndpointPort, "check TLSEndpointPort")
				require.Equal(t, tt.insecure, cc.TLSInsecure, "check TLSInsecure")

				if tt.wantCurveID != emptyString {
					require.Equal(t, tt.wantCurveID, cc.NegotiatedCurveID, "check NegotiatedCurveID")
				}

				return
			}

			//nolint:revive
			require.EqualError(t, err, tt.expectMsg, "check error expected")
		})
	}
}

//nolint:revive
func TestCertinfo_CertsToTables(t *testing.T) {
	rsaSampleCert, err := GetCertsFromBundle(
		RSASampleCertFile,
		inputReader,
	)
	require.NoError(t, err)

	rsaExpiredCert, err := GetCertsFromBundle(
		RSASamplePKCS8ExpiredCertificate,
		inputReader,
	)
	require.NoError(t, err)

	ecdsaCert, err := GetCertsFromBundle(
		ECDSASampleCertificate,
		inputReader,
	)
	require.NoError(t, err)

	ed25519Cert, err := GetCertsFromBundle(
		ED25519SampleCertificate,
		inputReader,
	)
	require.NoError(t, err)

	tests := []struct {
		desc               string
		cert               *x509.Certificate
		subject            string
		isCA               string
		expiration         string
		dnsNames           string
		publicKeyAlgorithm string
		signatureAlgorithm string
	}{
		{
			desc:               "RSA CA Cert",
			cert:               RSACaCertParent,
			subject:            "Subject             CN=RSA Testing CA",
			isCA:               "IsCA                true",
			expiration:         "Expiration          23 hours from now",
			dnsNames:           "DNSNames",
			publicKeyAlgorithm: "PublicKeyAlgorithm  RSA",
			signatureAlgorithm: "SignatureAlgorithm  SHA256-RSA",
		},
		{
			desc:               "RSA Cert",
			cert:               rsaSampleCert[0],
			subject:            "Subject             CN=RSA Testing Sample Certificate",
			isCA:               "IsCA                false",
			expiration:         "Expiration          23 hours from now",
			dnsNames:           "example.com",
			publicKeyAlgorithm: "PublicKeyAlgorithm  RSA",
			signatureAlgorithm: "SignatureAlgorithm  SHA256-RSA",
		},
		{
			desc:               "RSA Expired Cert",
			cert:               rsaExpiredCert[0],
			subject:            "Subject             CN=example.com,O=example Ltd,L=Berlin,ST=Some-State,C=DE",
			isCA:               "IsCA                false",
			expiration:         "ago",
			dnsNames:           "DNSNames",
			publicKeyAlgorithm: "PublicKeyAlgorithm  RSA",
			signatureAlgorithm: "SignatureAlgorithm  SHA256-RSA",
		},

		{
			desc:               "ECDSA CA Cert",
			cert:               ecdsaCert[0],
			subject:            "Subject             CN=example.com,O=Example Org",
			isCA:               "IsCA                true",
			dnsNames:           "DNSNames",
			publicKeyAlgorithm: "PublicKeyAlgorithm  ECDSA",
			signatureAlgorithm: "SignatureAlgorithm  ECDSA-SHA256",
		},
		{
			desc:               "ED25519 CA Cert",
			cert:               ed25519Cert[0],
			subject:            "Subject             CN=example.com,O=Example Org",
			isCA:               "IsCA                true",
			dnsNames:           "DNSNames",
			publicKeyAlgorithm: "PublicKeyAlgorithm  Ed25519",
			signatureAlgorithm: "SignatureAlgorithm  Ed25519",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.Buffer{}
			certs := []*x509.Certificate{
				tt.cert,
			}
			CertsToTables(&buffer, certs)

			got := buffer.String()

			for _, want := range []string{
				"Certificate",
				"Subject",
				"Issuer",
				"NotBefore",
				"NotAfter",
				"Expiration",
				"IsCA",
				"AuthorityKeyId",
				"SubjectKeyId",
				"PublicKeyAlgorithm",
				"SignatureAlgorithm",
				"SerialNumber",
				"Fingerprint SHA-256",
				tt.isCA,
				tt.dnsNames,
				tt.publicKeyAlgorithm,
				tt.signatureAlgorithm,
				tt.expiration,
			} {
				//nolint:revive
				require.Contains(t, got, want)
			}
		})
	}
}

func TestCertinfo_CertsToTables_FilteringAndWarning(t *testing.T) {
	warnCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "warning.example.com",
			Organization: []string{"Warning Corp"},
		},
		Issuer: pkix.Name{
			CommonName:   "warning.example.com",
			Organization: []string{"Warning Corp"},
		},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour), // 10 days -> warning (< 40 days)!
		Raw:          []byte("dummy raw cert bytes"),
		SerialNumber: big.NewInt(999),
		DNSNames:     []string{"warning.example.com", "alt.warning.example.com"},
	}

	t.Run("Warning Style", func(t *testing.T) {
		var buf bytes.Buffer
		CertsToTables(&buf, []*x509.Certificate{warnCert})
		got := buf.String()
		require.Contains(t, got, "warning.example.com")
		require.Contains(t, got, "1 week from now")
	})

	t.Run("Filtered Output", func(t *testing.T) {
		var buf bytes.Buffer

		filter := []map[int][]string{
			{
				0: []string{"Subject", "DNSNames"},
			},
		}
		CertsToTables(&buf, []*x509.Certificate{warnCert}, filter)
		got := buf.String()
		require.Contains(t, got, "Subject")
		require.Contains(t, got, "warning.example.com")
		require.Contains(t, got, "alt.warning.example.com")
		require.NotContains(t, got, "Issuer")
		require.NotContains(t, got, "NotAfter")
	})

	t.Run("Filtered Empty List", func(t *testing.T) {
		var buf bytes.Buffer

		filter := []map[int][]string{
			{
				0: []string{}, // empty list means print all fields for this cert
			},
		}
		CertsToTables(&buf, []*x509.Certificate{warnCert}, filter)
		got := buf.String()
		require.Contains(t, got, "Subject")
		require.Contains(t, got, "Issuer")
	})

	t.Run("Filtered Mismatched Index", func(t *testing.T) {
		var buf bytes.Buffer

		filter := []map[int][]string{
			{
				1: []string{"Subject"}, // index 1 doesn't exist for single cert, so cert 0 skipped
			},
		}
		CertsToTables(&buf, []*x509.Certificate{warnCert}, filter)
		got := buf.String()
		require.NotContains(t, got, "warning.example.com")
	})
}

//nolint:revive
func TestCertinfo_PrintData(t *testing.T) {
	tests := []struct {
		desc                string
		keyFile             string
		certFile            string
		caCertFile          string
		keyCertMatch        bool
		tlsEndpoint         string
		tlsInsecure         bool
		tlsServerName       string
		srvCfg              tlstest.ServerConfig
		expectCertsFetchErr bool
		expectCertsFetcMsg  string
	}{
		{
			desc:         "local CA cert and key",
			keyFile:      RSACaCertKeyFile,
			certFile:     RSACaCertFile,
			keyCertMatch: true,
		},
		{
			desc:         "local cert and key with CA",
			keyFile:      RSASampleCertKeyFile,
			certFile:     RSASampleCertFile,
			caCertFile:   RSACaCertFile,
			keyCertMatch: true,
		},
		{
			desc:          "local key and remote TLS Endpoint, certs validated",
			keyFile:       RSASampleCertKeyFile,
			caCertFile:    RSACaCertFile,
			keyCertMatch:  true,
			tlsServerName: "example.com",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
		},
		{
			desc:          "local key and remote TLS Endpoint, certs NOT validated",
			keyFile:       RSASampleCertKeyFile,
			caCertFile:    emptyString,
			tlsServerName: "example.com",
			//nolint:revive
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
				//nolint:revive
			},
			//nolint:revive
			expectCertsFetchErr: true,
			expectCertsFetcMsg:  "unable to get endpoint certificates: TLS handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},

		{
			desc:          "local key and remote TLS Endpoint, TLS Insecure",
			keyFile:       RSASampleCertKeyFile,
			caCertFile:    emptyString,
			keyCertMatch:  true,
			tlsInsecure:   true,
			tlsServerName: "example.com",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
		},
		{
			desc:       "local key and remote TLS Endpoint, missing TLS ServerName",
			keyFile:    RSASampleCertKeyFile,
			caCertFile: RSACaCertFile,
			//nolint:revive
			tlsServerName: emptyString,
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				//nolint:revive
				ServerKeyFile: RSASampleCertKeyFile,
				//nolint:revive
			},
			expectCertsFetchErr: true,
			expectCertsFetcMsg:  "unable to get endpoint certificates: TLS handshake failed: tls: failed to verify certificate: x509: certificate is valid for example.com, example.net, example.de, not localhost",
		},
		{
			desc:          "local key and remote TLS Endpoint, no key match",
			keyFile:       ED25519SamplePlaintextPrivateKey,
			caCertFile:    RSACaCertFile,
			keyCertMatch:  false,
			tlsServerName: "example.com",
			srvCfg: tlstest.ServerConfig{
				ServerCertFile: RSASampleCertFile,
				ServerKeyFile:  RSASampleCertKeyFile,
			},
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run("No errors test - "+tt.desc, func(t *testing.T) {
			t.Parallel()
			runPrintDataSubtest(t, tt)
		})
	}

	t.Run("PrintData local cert private key match error", func(t *testing.T) {
		buffer := bytes.Buffer{}
		cc, err := New()
		require.NoError(t, err)

		// Inject a bad public key to force certMatchPrivateKey to fail
		cc.PrivKey = "dummy_key"
		cc.CertsBundle = append(cc.CertsBundle, &x509.Certificate{
			PublicKey: "unsupported_key_type",
		})
		cc.CertsBundleFilePath = "dummy"

		errPrint := cc.PrintData(context.Background(), &buffer)
		require.Error(t, errPrint)
		require.ErrorContains(t, errPrint, "unable to check if private key matches local certificate")
	})

	t.Run("PrintData remote cert private key match error", func(t *testing.T) {
		buffer := bytes.Buffer{}
		cc, err := New()
		require.NoError(t, err)

		cc.PrivKey = "dummy_key"
		cc.TLSEndpointCerts = append(cc.TLSEndpointCerts, &x509.Certificate{
			PublicKey: "unsupported_key_type",
		})
		cc.TLSEndpointHost = "localhost"
		cc.TLSEndpointPort = "443"

		errPrint := cc.PrintData(context.Background(), &buffer)
		require.Error(t, errPrint)
		require.ErrorContains(t, errPrint, "unable to check if private key matches remote TLS Endpoint certificate")
	})

	t.Run("PrintData CA cert file read error", func(t *testing.T) {
		buffer := bytes.Buffer{}
		cc, err := New()
		require.NoError(t, err)

		cc.CACertsFilePath = "non_existent_file.pem"

		errPrint := cc.PrintData(context.Background(), &buffer)
		require.Error(t, errPrint)
		require.ErrorContains(t, errPrint, "unable for read Root certificates")
	})
}

type printDataTestCase struct {
	desc                string
	keyFile             string
	certFile            string
	caCertFile          string
	keyCertMatch        bool
	tlsEndpoint         string
	tlsInsecure         bool
	tlsServerName       string
	srvCfg              tlstest.ServerConfig
	expectCertsFetchErr bool
	expectCertsFetcMsg  string
}

func runPrintDataSubtest(t *testing.T, tt printDataTestCase) {
	buffer := bytes.Buffer{}

	cc, err := New()
	require.NoError(t, err)

	require.NoError(t, cc.SetPrivateKeyFromFile(tt.keyFile, "notSet", inputReader))
	require.NoError(t, cc.SetCertsFromFile(tt.certFile, inputReader))
	require.NoError(t, cc.SetCaPoolFromFile(tt.caCertFile, inputReader))

	if tt.srvCfg.ServerCertFile != emptyString {
		ts, errSrv := tlstest.NewServer(tt.srvCfg)
		require.NoError(t, errSrv)
		t.Cleanup(ts.Close)

		tt.tlsEndpoint = ts.Listener.Addr().String()
		if tt.tlsServerName == emptyString {
			// Cert SANs include 127.0.0.1; dial by hostname so empty SNI still mismatches.
			_, port, splitErr := net.SplitHostPort(tt.tlsEndpoint)
			require.NoError(t, splitErr)

			tt.tlsEndpoint = net.JoinHostPort("localhost", port)
		}

		cc.SetTLSServerName(tt.tlsServerName)
		cc.SetTLSInsecure(tt.tlsInsecure)

		err = cc.SetTLSEndpoint(t.Context(), tt.tlsEndpoint)
		if tt.expectCertsFetchErr {
			require.EqualError(t, err, tt.expectCertsFetcMsg)
		} else {
			require.NoError(t, err, "SetTLSEndpoint require NoError")
		}
	}

	errPrint := cc.PrintData(context.Background(), &buffer)
	require.NoError(t, errPrint)

	got := buffer.String()
	verifyPrintDataOutput(t, got, tt)
}

func verifyPrintDataOutput(t *testing.T, got string, tt printDataTestCase) {
	if tt.keyFile != emptyString {
		require.Contains(t, got, "PrivateKey file: "+tt.keyFile)
	}

	if tt.certFile != emptyString {
		require.Contains(t, got, "Certificate bundle file: "+tt.certFile)
	}

	if tt.caCertFile != emptyString {
		require.Contains(t, got, "CA Certificates file: "+tt.caCertFile)
	}

	if tt.expectCertsFetchErr {
		return
	}

	for _, want := range []string{
		"Certinfo", "Certificate", "Subject", "Issuer", "NotBefore", "NotAfter",
		"Expiration", "IsCA", "AuthorityKeyId", "SubjectKeyId", "PublicKeyAlgorithm",
		"SignatureAlgorithm", "SerialNumber", "Fingerprint SHA-256",
	} {
		require.Contains(t, got, want)
	}

	if tt.keyFile != emptyString {
		if tt.keyCertMatch {
			require.Contains(t, got, "PrivateKey match: true")
		} else {
			require.Contains(t, got, "PrivateKey match: false")
		}
	}

	if tt.tlsEndpoint != emptyString {
		require.Contains(t, got, "TLSEndpoint Certificates")
		require.Contains(t, got, "Endpoint: "+tt.tlsEndpoint)
		require.Contains(t, got, "ServerName: "+tt.tlsServerName)
	}
}
