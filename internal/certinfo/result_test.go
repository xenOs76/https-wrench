/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func TestBuildResult_EncodeJSON(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)
	require.NoError(t, cc.SetCertsFromFile(RSASampleCertFile, inputReader))
	require.NoError(t, cc.SetPrivateKeyFromFile(RSASampleCertKeyFile, "notSet", inputReader))

	result, err := cc.BuildResult()
	require.NoError(t, err)
	require.Equal(t, ResultSchemaVersion, result.SchemaVersion)
	require.Equal(t, "certinfo", result.Command)
	require.NotNil(t, result.LocalCerts)
	require.NotNil(t, result.PrivateKey)
	require.NotNil(t, result.LocalCerts.PrivateKeyMatch)
	require.True(t, *result.LocalCerts.PrivateKeyMatch)

	payload, err := EncodeJSON(result)
	require.NoError(t, err)
	require.NotContains(t, string(payload), "\x1b[")

	var decoded Result
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, ResultSchemaVersion, decoded.SchemaVersion)
	require.Len(t, decoded.LocalCerts.Certificates, 1)
	require.Contains(t, decoded.LocalCerts.Certificates[0].Subject, "RSA Testing Sample Certificate")
}

func TestBuildDoc_PlainHasNoANSI(t *testing.T) {
	t.Parallel()

	cc, err := New()
	require.NoError(t, err)
	require.NoError(t, cc.SetCertsFromFile(RSASampleCertFile, inputReader))

	var buf bytes.Buffer
	require.NoError(t, cc.PrintDataWithOptions(&buf, view.Options{Plain: true}))
	require.Contains(t, buf.String(), "Certinfo")
	require.NotContains(t, buf.String(), "\x1b[")
}
