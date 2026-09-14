package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/jwks"
)

func writeTestRSAPublicKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	path := filepath.Join(t.TempDir(), "rsa_public.pem")
	f, err := os.Create(path)
	require.NoError(t, err)

	defer f.Close()

	err = pem.Encode(f, block)
	require.NoError(t, err)

	return path
}

func resetJWKSFlags() {
	jwksPublicKeyFile = ""
	jwksKID = ""
	jwksFmt = "text"
}

func TestJWKSCmd_Errors(t *testing.T) {
	t.Parallel()

	t.Run("unsupported format", func(t *testing.T) {
		resetJWKSFlags()

		jwksPublicKeyFile = "some.pem"
		jwksFmt = "yaml"

		out := new(bytes.Buffer)
		jwksCmd.SetOut(out)
		jwksCmd.SetErr(out)
		jwksCmd.SetContext(context.Background())

		jwksCmd.Run(jwksCmd, nil)

		got := out.String()
		require.Contains(t, got, `Error: unsupported --format "yaml" (use text or json)`)
	})

	t.Run("invalid file", func(t *testing.T) {
		resetJWKSFlags()

		jwksPublicKeyFile = "non_existent_file.pem"

		errOut := new(bytes.Buffer)
		jwksCmd.SetErr(errOut)
		jwksCmd.SetContext(context.Background())

		jwksCmd.Run(jwksCmd, nil)

		got := errOut.String()
		require.Contains(t, got, "Error generating JWKS:")
		require.Contains(t, got, "no such file or directory")
	})
}

func TestJWKSCmd_Success(t *testing.T) {
	pubFile := writeTestRSAPublicKeyPEM(t)

	t.Run("default text format", func(t *testing.T) {
		resetJWKSFlags()

		jwksPublicKeyFile = pubFile

		out := new(bytes.Buffer)
		jwksCmd.SetOut(out)
		jwksCmd.SetErr(out)
		jwksCmd.SetContext(context.Background())

		jwksCmd.Run(jwksCmd, nil)

		got := out.String()
		require.Contains(t, got, "Jwks")
		require.Contains(t, got, `"kty": "RSA"`)
		require.Contains(t, got, `"keys"`)
	})

	t.Run("explicit kid text format", func(t *testing.T) {
		resetJWKSFlags()

		jwksPublicKeyFile = pubFile
		jwksKID = "custom-kid-123"

		out := new(bytes.Buffer)
		jwksCmd.SetOut(out)
		jwksCmd.SetErr(out)
		jwksCmd.SetContext(context.Background())

		jwksCmd.Run(jwksCmd, nil)

		got := out.String()
		require.Contains(t, got, "custom-kid-123")
	})

	t.Run("json format", func(t *testing.T) {
		resetJWKSFlags()

		jwksPublicKeyFile = pubFile
		jwksFmt = "json"

		out := new(bytes.Buffer)
		jwksCmd.SetOut(out)
		jwksCmd.SetErr(out)
		jwksCmd.SetContext(context.Background())

		jwksCmd.Run(jwksCmd, nil)

		got := out.String()
		require.NotContains(t, got, "\x1b[", "JSON output must not contain ANSI escape codes")

		var res jwks.Result

		err := json.Unmarshal([]byte(got), &res)
		require.NoError(t, err)
		require.Equal(t, jwks.ResultSchemaVersion, res.SchemaVersion)
		require.Equal(t, "jwks", res.Command)
		require.Len(t, res.Keys, 1)
		require.Contains(t, string(res.Keys[0]), `"kty": "RSA"`)
	})
}
