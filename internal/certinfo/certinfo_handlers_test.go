package certinfo

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertinfo_GetRemoteCerts(t *testing.T) {
	tests := []struct {
		desc          string
		srvCfg        demoHTTPServerConfig
		caCertFile    string
		insecure      bool
		expectSrvHost string
		expectSrvPort string
		expectError   bool
		expectMsg     string
	}{
		{
			desc: "RSA Cert Success",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46301",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:    RSACaCertFile,
			expectSrvHost: "localhost",
			expectSrvPort: "46301",
		},
		{
			desc: "Error Secure and No CA Cert",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46302",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:  emptyString,
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},

		{
			desc: "Malfomed Server Certificate",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46303",
				serverName:     "example.com",
				serverCertFile: RSASamplePKCS8Certificate,
				serverKeyFile:  RSASamplePKCS8PlaintextPrivateKey,
			},
			caCertFile:    RSACaCertFile,
			expectSrvHost: "localhost",
			expectSrvPort: "46303",
			expectError:   true,
			expectMsg:     "TLS handshake failed: tls: failed to verify certificate: x509: certificate relies on legacy Common Name field, use SANs instead",
		},
		{
			desc: "No CA Cert and Insecure",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46304",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			insecure:      true,
			expectSrvHost: "localhost",
			expectSrvPort: "46304",
			caCertFile:    emptyString,
		},
		{
			desc: "Wrong CA Cert and Secure",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46305",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:    RSASamplePKCS8Certificate,
			expectSrvHost: "localhost",
			expectSrvPort: "46305",
			expectError:   true,
			expectMsg:     "TLS handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
		{
			desc: "Wrong CA Cert and Insecure",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46306",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:    RSASamplePKCS8Certificate,
			insecure:      true,
			expectSrvHost: "localhost",
			expectSrvPort: "46306",
		},
		{
			desc: "IPV6 Enpoint RSA Cert Success",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "[::1]:46307",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:    RSACaCertFile,
			expectSrvHost: "::1",
			expectSrvPort: "46307",
		},
		{
			desc: "Error wrong ServerName",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46308",
				serverName:     "example.co.uk",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
			caCertFile:  RSACaCertFile,
			expectError: true,
			expectMsg:   "TLS handshake failed: tls: failed to verify certificate: x509: certificate is valid for example.com, example.net, example.de, not example.co.uk",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			ts, err := NewHTTPSTestServer(tt.srvCfg)
			require.NoError(t, err)

			defer ts.Close()

			cc, err := NewCertinfoConfig()
			require.NoError(t, err)

			cc.SetTLSServerName(tt.srvCfg.serverName)
			cc.SetCaPoolFromFile(tt.caCertFile, inputReader)
			cc.SetTLSEndpoint(tt.srvCfg.serverAddr)
			cc.SetTLSInsecure(tt.insecure)

			err = cc.GetRemoteCerts()
			if !tt.expectError {
				require.NoError(t, err, "check error not expected")
				require.Equal(t, tt.srvCfg.serverName, cc.TLSServerName, "check TLSServerName")
				require.Equal(t, tt.expectSrvHost, cc.TLSEndpointHost, "check TLSEndpointHost")
				require.Equal(t, tt.expectSrvPort, cc.TLSEndpointPort, "check TLSEndpointPort")
				require.Equal(t, tt.insecure, cc.TLSInsecure, "check TLSInsecure")

				return
			}

			require.EqualError(t, err, tt.expectMsg, "check error expected")
		})
	}
}

func TestCertinfo_CertsToTables(t *testing.T) {
	rsaSampleCert, err := GetCertsFromBundle(
		RSASampleCertFile,
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
		// TODO: add expired cert case
		{
			desc:               "RSA CA Cert",
			cert:               RSACaCertParent,
			subject:            "Subject             CN=RSA Testing CA",
			isCA:               "IsCA                true",
			expiration:         "Expiration          23 hours from now",
			dnsNames:           "DNSNames            []",
			publicKeyAlgorithm: "PublicKeyAlgorithm  RSA",
			signatureAlgorithm: "SignatureAlgorithm  SHA256-RSA",
		},
		{
			desc:               "RSA Cert",
			cert:               rsaSampleCert[0],
			subject:            "Subject             CN=RSA Testing Sample Certificate",
			isCA:               "IsCA                false",
			expiration:         "Expiration          23 hours from now",
			dnsNames:           "DNSNames            [example.com, example.net, example.de]",
			publicKeyAlgorithm: "PublicKeyAlgorithm  RSA",
			signatureAlgorithm: "SignatureAlgorithm  SHA256-RSA",
		},
		{
			desc:               "ECDSA CA Cert",
			cert:               ecdsaCert[0],
			subject:            "Subject             CN=example.com,O=Example Org",
			isCA:               "IsCA                true",
			dnsNames:           "DNSNames            []",
			publicKeyAlgorithm: "PublicKeyAlgorithm  ECDSA",
			signatureAlgorithm: "SignatureAlgorithm  ECDSA-SHA256",
		},
		{
			desc:               "ED25519 CA Cert",
			cert:               ed25519Cert[0],
			subject:            "Subject             CN=example.com,O=Example Org",
			isCA:               "IsCA                true",
			dnsNames:           "DNSNames            []",
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
			} {
				require.Contains(t, got, want)
			}
		})
	}
}

func TestCertinfo_PrintData(t *testing.T) {
	noErrorsTests := []struct {
		desc         string
		keyFile      string
		certFile     string
		caCertFile   string
		keyCertMatch bool
		tlsEndpoint  string
		srvCfg       demoHTTPServerConfig
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
			desc:         "local key and remote TLS Enpoint",
			keyFile:      RSASampleCertKeyFile,
			caCertFile:   RSACaCertFile,
			keyCertMatch: true,
			tlsEndpoint:  "localhost:46401",
			srvCfg: demoHTTPServerConfig{
				serverAddr:     "localhost:46401",
				serverName:     "example.com",
				serverCertFile: RSASampleCertFile,
				serverKeyFile:  RSASampleCertKeyFile,
			},
		},
	}

	for _, tc := range noErrorsTests {
		tt := tc
		t.Run("No errors test - "+tt.desc, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.Buffer{}

			cc, err := NewCertinfoConfig()
			require.NoError(t, err)

			cc.SetPrivateKeyFromFile(tt.keyFile, "notSet", inputReader)
			cc.SetCertsFromFile(tt.certFile, inputReader)
			cc.SetCaPoolFromFile(tt.caCertFile, inputReader)

			if tt.tlsEndpoint != emptyString {
				ts, errSrv := NewHTTPSTestServer(tt.srvCfg)
				require.NoError(t, errSrv)

				defer ts.Close()

				cc.SetTLSServerName(tt.srvCfg.serverName)
				cc.SetTLSEndpoint(tt.tlsEndpoint)
			}

			errPrint := cc.PrintData(&buffer)
			require.NoError(t, errPrint)

			got := buffer.String()
			for _, want := range []string{
				"Certinfo",
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
			} {
				require.Contains(t, got, want)
			}

			if tt.keyFile != emptyString {
				require.Contains(t, got, "PrivateKey file: "+tt.keyFile)
			}

			if tt.certFile != emptyString {
				require.Contains(t, got, "Certificate bundle file: "+tt.certFile)
			}

			if tt.caCertFile != emptyString {
				require.Contains(t, got, "CA Certificates file: "+tt.caCertFile)
			}

			if tt.keyFile != emptyString && tt.keyCertMatch {
				require.Contains(t, got, "PrivateKey match: true")
			} else {
				require.Contains(t, got, "PrivateKey match: false")
			}

			if tt.tlsEndpoint != emptyString {
				require.Contains(t, got, "TLSEndpoint Certificates")
				require.Contains(t, got, "Endpoint: "+tt.tlsEndpoint)
				require.Contains(t, got, "ServerName: "+tt.srvCfg.serverName)
			}
		})
	}
}
