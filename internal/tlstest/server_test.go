package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type leafFiles struct {
	certFile string
	keyFile  string
	caCert   *x509.Certificate
}

func writeLeafFiles(t *testing.T) leafFiles {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, caCert, err := GenerateCert(Template{
		CN:   "tlstest CA",
		IsCA: true,
		Key:  caKey,
	})
	require.NoError(t, err)

	leafPEM, _, err := GenerateCert(Template{
		CN:          "localhost",
		Key:         leafKey,
		CAKey:       caKey,
		Parent:      caCert,
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
	})
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "leaf.pem")
	keyFile := filepath.Join(dir, "leaf.key")

	require.NoError(t, os.WriteFile(certFile, leafPEM, 0o600))

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(leafKey),
	})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return leafFiles{
		certFile: certFile,
		keyFile:  keyFile,
		caCert:   caCert,
	}
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	leaf := writeLeafFiles(t)

	ts, err := NewServer(ServerConfig{
		ListenHost:     "127.0.0.1",
		ServerCertFile: leaf.certFile,
		ServerKeyFile:  leaf.keyFile,
	})
	require.NoError(t, err)
	t.Cleanup(ts.Close)
	require.Nil(t, ts.TLS.CipherSuites)

	pool := x509.NewCertPool()
	pool.AddCert(leaf.caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	res, err := client.Get(ts.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusOK, res.StatusCode)
}

func TestNewServerTLS12ConfiguredCipher(t *testing.T) {
	t.Parallel()

	leaf := writeLeafFiles(t)
	suite := tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

	ts, err := NewServer(ServerConfig{
		ListenHost:      "127.0.0.1",
		ServerCertFile:  leaf.certFile,
		ServerKeyFile:   leaf.keyFile,
		TLSMaxVersion:   tls.VersionTLS12,
		TLSCipherSuites: []uint16{suite},
	})
	require.NoError(t, err)
	t.Cleanup(ts.Close)

	pool := x509.NewCertPool()
	pool.AddCert(leaf.caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{suite},
			},
		},
	}

	res, err := client.Get(ts.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NotNil(t, res.TLS)
	require.Equal(t, uint16(tls.VersionTLS12), res.TLS.Version)
	require.Equal(t, suite, res.TLS.CipherSuite)
}

func TestNewServerRejectsTLS13CipherSuite(t *testing.T) {
	t.Parallel()

	leaf := writeLeafFiles(t)

	_, err := NewServer(ServerConfig{
		ListenHost:      "127.0.0.1",
		ServerCertFile:  leaf.certFile,
		ServerKeyFile:   leaf.keyFile,
		TLSCipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
	})
	require.Error(t, err)
}

func TestNewServerMissingCertClosesListener(t *testing.T) {
	t.Parallel()

	_, err := NewServer(ServerConfig{
		ListenHost:     "127.0.0.1",
		ServerCertFile: filepath.Join(t.TempDir(), "missing.pem"),
		ServerKeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	})
	require.Error(t, err)
}
