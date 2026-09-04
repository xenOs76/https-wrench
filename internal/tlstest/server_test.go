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

func TestNewServer(t *testing.T) {
	t.Parallel()

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

	ts, err := NewServer(ServerConfig{
		ListenHost:     "127.0.0.1",
		ServerCertFile: certFile,
		ServerKeyFile:  keyFile,
	})
	require.NoError(t, err)
	t.Cleanup(ts.Close)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

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

func TestNewServerMissingCertClosesListener(t *testing.T) {
	t.Parallel()

	_, err := NewServer(ServerConfig{
		ListenHost:     "127.0.0.1",
		ServerCertFile: filepath.Join(t.TempDir(), "missing.pem"),
		ServerKeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	})
	require.Error(t, err)
}
