// Package jwks provides functionality for generating JSON Web Key Sets (JWKS) from public keys.
package jwks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/MicahParks/jwkset"
)

// GenerateJWKS reads a public key from a file, parses it, and returns its JSON Web Key Set (JWKS) representation.
// If kid is provided, it sets the Key ID explicitly; otherwise, it computes a SHA-256-derived kid from the public key.
func GenerateJWKS(ctx context.Context, publicKeyFile string, kid string) (string, error) {
	keyPEM, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return "", fmt.Errorf("unable to read public key from %s: %w", publicKeyFile, err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", errors.New("failed to decode PEM block from public key file")
	}

	key, err := jwkset.LoadX509KeyInfer(block)
	if err != nil {
		return "", fmt.Errorf("unsupported or invalid public key format: %w", err)
	}

	// Ensure the key is a public key
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		// Valid public key types
	default:
		return "", errors.New("the provided file does not contain a supported public key " +
			"(it might be a private key or an unsupported format)")
	}

	if kid == "" {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", fmt.Errorf("failed to marshal public key for SHA-256-derived kid: %w", err)
		}

		hash := sha256.Sum256(pubBytes)
		kid = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	options := jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: kid,
		},
	}

	// Create JWK from the parsed public key
	jwk, err := jwkset.NewJWKFromKey(key, options)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Initialize in-memory storage for the JWK Set
	storage := jwkset.NewMemoryStorage()

	err = storage.KeyWrite(ctx, jwk)
	if err != nil {
		return "", fmt.Errorf("failed to write key to JWK Set storage: %w", err)
	}

	jwksBytes, err := storage.JSONPublic(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWKS JSON: %w", err)
	}

	// Pretty-print the JSON
	var prettyJWKS bytes.Buffer
	if err := json.Indent(&prettyJWKS, jwksBytes, "", "  "); err != nil {
		return string(jwksBytes), nil
	}

	return prettyJWKS.String(), nil
}
