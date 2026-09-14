// Package jwks provides functionality for generating JSON Web Key Sets (JWKS) from public keys.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/MicahParks/jwkset"
)

// Generate reads a public key from a file, parses it, and returns its typed Result.
// If kid is provided, it sets the Key ID explicitly; otherwise, it computes a SHA-256-derived kid from the public key.
func Generate(ctx context.Context, publicKeyFile string, kid string) (*Result, error) {
	keyPEM, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read public key from %s: %w", publicKeyFile, err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, ErrPEMDecode
	}

	key, err := jwkset.LoadX509KeyInfer(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedPublicKey, err)
	}

	// Ensure the key is a public key
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		// Valid public key types
	default:
		return nil, ErrNotPublicKey
	}

	if kid == "" {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key for SHA-256-derived kid: %w", err)
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
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Initialize in-memory storage for the JWK Set
	storage := jwkset.NewMemoryStorage()

	err = storage.KeyWrite(ctx, jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to write key to JWK Set storage: %w", err)
	}

	jwksBytes, err := storage.JSONPublic(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWKS JSON: %w", err)
	}

	var parsed struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwksBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse generated JWKS JSON: %w", err)
	}

	return &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
		Keys:          parsed.Keys,
	}, nil
}

// GenerateJWKS reads a public key from a file, parses it, and returns its JSON Web Key Set (JWKS) representation.
// If kid is provided, it sets the Key ID explicitly; otherwise, it computes a SHA-256-derived kid from the public key.
func GenerateJWKS(ctx context.Context, publicKeyFile string, kid string) (string, error) {
	res, err := Generate(ctx, publicKeyFile, kid)
	if err != nil {
		return "", err
	}

	return res.JWKSJSON()
}
