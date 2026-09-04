package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateCert(t *testing.T) {
	t.Parallel()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caPEM, caCert, err := GenerateCert(Template{
		CN:   "tlstest CA",
		IsCA: true,
		Key:  caKey,
	})
	require.NoError(t, err)
	require.True(t, caCert.IsCA)
	require.True(t, caCert.BasicConstraintsValid)
	require.Equal(t, "tlstest CA", caCert.Subject.CommonName)
	require.NotEmpty(t, caPEM)

	block, _ := pem.Decode(caPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	wantDNS := []string{"example.com", "example.net"}
	wantIPs := []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")}

	leafPEM, leafCert, err := GenerateCert(Template{
		CN:          "example.com",
		Key:         leafKey,
		CAKey:       caKey,
		Parent:      caCert,
		DNSNames:    wantDNS,
		IPAddresses: wantIPs,
	})
	require.NoError(t, err)
	require.False(t, leafCert.IsCA)
	require.Equal(t, "example.com", leafCert.Subject.CommonName)
	require.Equal(t, wantDNS, leafCert.DNSNames)
	require.Len(t, leafCert.IPAddresses, 2)
	require.True(t, leafCert.IPAddresses[0].Equal(wantIPs[0]))
	require.True(t, leafCert.IPAddresses[1].Equal(wantIPs[1]))
	require.NotEmpty(t, leafPEM)
	require.NoError(t, leafCert.CheckSignatureFrom(caCert))
}

func TestGenerateCert_missingKey(t *testing.T) {
	t.Parallel()

	_, _, err := GenerateCert(Template{
		CN:   "broken",
		IsCA: true,
	})
	require.Error(t, err)
}

func TestGenerateCert_missingIssuer(t *testing.T) {
	t.Parallel()

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, caCert, err := GenerateCert(Template{
		CN:   "tlstest CA",
		IsCA: true,
		Key:  caKey,
	})
	require.NoError(t, err)

	t.Run("missing parent", func(t *testing.T) {
		t.Parallel()

		_, _, err := GenerateCert(Template{
			CN:    "example.com",
			Key:   leafKey,
			CAKey: caKey,
		})
		require.ErrorContains(t, err, "parent certificate")
	})

	t.Run("missing CA key", func(t *testing.T) {
		t.Parallel()

		_, _, err := GenerateCert(Template{
			CN:     "example.com",
			Key:    leafKey,
			Parent: caCert,
		})
		require.ErrorContains(t, err, "CA private key")
	})
}
