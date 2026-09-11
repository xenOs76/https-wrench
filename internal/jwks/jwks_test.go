package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateJWKS_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Helper to create a PEM file
	createPEM := func(t *testing.T, filename, blockType string, bytes []byte) string {
		t.Helper()

		path := filepath.Join(tmpDir, filename)
		block := &pem.Block{
			Type:  blockType,
			Bytes: bytes,
		}
		file, err := os.Create(path)
		require.NoError(t, err)
		err = pem.Encode(file, block)
		require.NoError(t, err)
		require.NoError(t, file.Close())

		return path
	}

	// RSA Setup
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPubBytes, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	require.NoError(t, err)
	rsaPubFile := createPEM(t, "rsa_public.pem", "PUBLIC KEY", rsaPubBytes)

	// ECDSA Setup
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	require.NoError(t, err)
	ecdsaPubFile := createPEM(t, "ecdsa_public.pem", "PUBLIC KEY", ecdsaPubBytes)

	// Ed25519 Setup
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPubBytes, err := x509.MarshalPKIXPublicKey(edPub)
	require.NoError(t, err)
	edPubFile := createPEM(t, "ed25519_public.pem", "PUBLIC KEY", edPubBytes)

	t.Run("RSA", func(t *testing.T) {
		jwksJSON, err := GenerateJWKS(context.Background(), rsaPubFile, "")
		require.NoError(t, err)
		require.Contains(t, jwksJSON, `"kty": "RSA"`)
		require.Contains(t, jwksJSON, `"kid":`)
	})

	t.Run("ECDSA", func(t *testing.T) {
		jwksJSON, err := GenerateJWKS(context.Background(), ecdsaPubFile, "")
		require.NoError(t, err)
		require.Contains(t, jwksJSON, `"kty": "EC"`)
		require.Contains(t, jwksJSON, `"crv": "P-256"`)
		require.Contains(t, jwksJSON, `"kid":`)
	})

	t.Run("Ed25519", func(t *testing.T) {
		jwksJSON, err := GenerateJWKS(context.Background(), edPubFile, "")
		require.NoError(t, err)
		require.Contains(t, jwksJSON, `"kty": "OKP"`)
		require.Contains(t, jwksJSON, `"crv": "Ed25519"`)
		require.Contains(t, jwksJSON, `"kid":`)
	})

	t.Run("Explicit KID", func(t *testing.T) {
		expectedKID := "my-custom-kid"
		jwksJSON, err := GenerateJWKS(context.Background(), rsaPubFile, expectedKID)
		require.NoError(t, err)
		require.Contains(t, jwksJSON, `"kid": "`+expectedKID+`"`)
	})
}

func TestGenerateJWKS_Errors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Invalid file", func(t *testing.T) {
		_, err := GenerateJWKS(context.Background(), "non-existent-file.pem", "")
		require.Error(t, err)
		require.ErrorContains(t, err, "unable to read public key from")
	})

	t.Run("Invalid PEM", func(t *testing.T) {
		invalidFile := filepath.Join(tmpDir, "invalid.pem")
		err := os.WriteFile(invalidFile, []byte("not a pem"), 0o644)
		require.NoError(t, err)

		_, err = GenerateJWKS(context.Background(), invalidFile, "")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to decode PEM block")
	})

	t.Run("Unsupported block type", func(t *testing.T) {
		path := filepath.Join(tmpDir, "unsupported.pem")
		block := &pem.Block{Type: "NOT A KEY", Bytes: []byte("random data")}
		file, _ := os.Create(path)
		_ = pem.Encode(file, block)
		file.Close()

		_, err := GenerateJWKS(context.Background(), path, "")
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported or invalid public key format")
	})

	t.Run("Private key rejected", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		path := filepath.Join(tmpDir, "private.pem")
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		file, _ := os.Create(path)
		_ = pem.Encode(file, block)
		file.Close()

		_, err := GenerateJWKS(context.Background(), path, "")
		require.Error(t, err)
		require.ErrorContains(t, err, "does not contain a supported public key")
	})
}
