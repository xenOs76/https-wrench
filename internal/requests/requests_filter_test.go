package requests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCert(t *testing.T) *x509.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Corp"},
			CommonName:   "example.com",
		},
		Issuer: pkix.Name{
			Organization: []string{"Acme Authority"},
			CommonName:   "CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "www.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	return cert
}

func TestRenderTLSData_Filtering(t *testing.T) {
	cert := createTestCert(t)

	resp := &http.Response{
		TLS: &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	t.Run("No Filter", func(t *testing.T) {
		var buf bytes.Buffer
		RenderTLSData(&buf, resp)

		output := buf.String()
		assert.Contains(t, output, "TLS:")
		assert.Contains(t, output, "Version")
		assert.Contains(t, output, "TLS 1.3")
		assert.Contains(t, output, "Subject")
		assert.Contains(t, output, "example.com")
		assert.Contains(t, output, "Issuer")
		assert.Contains(t, output, "Acme Corp")
		assert.Contains(t, output, "DNSNames")
		assert.Contains(t, output, "www.example.com")
	})

	t.Run("Filter Cert 0 with specific fields", func(t *testing.T) {
		var buf bytes.Buffer

		filter := []map[int][]string{
			{
				0: []string{"Subject", "DNSNames"},
			},
		}
		RenderTLSData(&buf, resp, filter)

		output := buf.String()
		assert.Contains(t, output, "TLS:")
		assert.Contains(t, output, "Subject")
		assert.Contains(t, output, "example.com")
		assert.Contains(t, output, "DNSNames")
		assert.Contains(t, output, "www.example.com")

		// Filtered-out fields should NOT be in the output
		assert.NotContains(t, output, "Issuer")
		assert.NotContains(t, output, "NotBefore")
		assert.NotContains(t, output, "Expiration")
	})

	t.Run("Filter Non-existent Cert Index", func(t *testing.T) {
		var buf bytes.Buffer

		filter := []map[int][]string{
			{
				1: []string{"Subject"}, // Certificate 1 does not exist in chain
			},
		}
		RenderTLSData(&buf, resp, filter)

		output := buf.String()
		assert.Contains(t, output, "TLS:")
		// Output should NOT contain Certificate 0 information
		assert.NotContains(t, output, "Certificate 0")
		assert.NotContains(t, output, "Subject")
	})
}
