package style

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func RSAGenerateKey(bits int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	return priv, nil
}

func ECDSAGenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	return priv, nil
}

func ED25519GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ED25519 private key: %w", err)
	}

	return priv, nil
}

func TestPrintKeyInfoStyle(t *testing.T) {
	rsaKey, rsaErr := RSAGenerateKey(2048)
	require.NoError(t, rsaErr)

	ecdsaKey, ecdsaErr := ECDSAGenerateKey(elliptic.P256())
	require.NoError(t, ecdsaErr)

	ed25519Key, edErr := ED25519GenerateKey()
	require.NoError(t, edErr)

	var fakeKey crypto.PrivateKey

	tests := []struct {
		name         string
		key          crypto.PrivateKey
		expectedType string
	}{
		{
			name:         "rsa private key",
			key:          rsaKey,
			expectedType: "RSA",
		},
		{
			name:         "ecdsa private key",
			key:          ecdsaKey,
			expectedType: "ECDSA",
		},

		{
			name:         "ed21219 private key",
			key:          ed25519Key,
			expectedType: "ED25519",
		},

		{
			name:         "fake private key",
			key:          fakeKey,
			expectedType: "Unknown",
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			PrintKeyInfoStyle(&buffer, tt.key)

			got := buffer.String()

			require.Contains(t, got, tt.expectedType)
		})
	}
}

func TestLgSprintf(t *testing.T) {
	tests := []string{
		"a string",
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt, func(t *testing.T) {
			t.Parallel()

			simple := LgSprintf(Status, "%s", tt)
			require.Equal(t, tt, simple)

			pattern := LgSprintf(Status, "%s - lorem ipsum", tt)
			require.Equal(t, tt+" - lorem ipsum", pattern)
		})
	}
}

func TestStatusCodeParse(t *testing.T) {
	tests := []struct {
		statusInt    int
		statusString string
	}{
		{0, "0"},
		{200, "200"},
		{300, "300"},
		{400, "400"},
		{500, "500"},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.statusString, func(t *testing.T) {
			t.Parallel()

			s := StatusCodeParse(tt.statusInt)
			require.Equal(t, tt.statusString, s)
		})
	}
}

func TestBoolStyle(t *testing.T) {
	tests := []struct {
		statusBool   bool
		statusString string
	}{
		{true, "true"},
		{false, "false"},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.statusString, func(t *testing.T) {
			t.Parallel()

			s := BoolStyle(tt.statusBool)
			require.Equal(t, tt.statusString, s)
		})
	}
}

func TestCodeSyntaxHighlight(t *testing.T) {
	tests := []struct {
		lang   string
		code   string
		expect []string
	}{
		{
			lang: "html",
			code: `
				<html>
				  <head>
				    <title>Div Align Attribute</title>
				  </head>
				  <body>
				    <div align="left">
				      Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
				      labore et dolore magna aliqua.
				    </div>
				  </body>
				</html>
			`,
			expect: []string{
				"Lorem ipsum dolor sit amet, consectetur adipiscing elit",
				"sed do eiusmod tempor incididunt ut",
			},
		},
		{
			lang: "yaml",
			code: `
				---
				# yaml document beginning
				# comment syntax

				name: John Doe
				age: 30

				fruits:
				  - Apple
				  - Banana
				  - Cherry

				person:
				  name: John Doe
				  age: 30
				  address:
				    street: '123 Main St'
				    city: Example City
			`,
			expect: []string{
				"123 Main St",
				"John Doe",
				"Apple",
				"Banana",
			},
		},

		{
			lang: "NoCode",
			code: "test",
			expect: []string{
				"test",
			},
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.lang, func(t *testing.T) {
			t.Parallel()

			s := CodeSyntaxHighlight(tt.lang, tt.code)
			for _, expect := range tt.expect {
				require.Contains(t, s, expect)
			}
		})
	}
}
