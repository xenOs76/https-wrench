package certinfo

import (
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
