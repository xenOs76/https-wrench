package jwks

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResult_EncodeJSON(t *testing.T) {
	t.Parallel()

	res := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
		Keys: []json.RawMessage{
			json.RawMessage(`{"kty":"RSA","kid":"test-key-id","n":"abc","e":"AQAB"}`),
		},
	}

	payload, err := EncodeJSON(res)
	require.NoError(t, err)

	got := string(payload)
	require.Contains(t, got, `"schemaVersion": "1"`)
	require.Contains(t, got, `"command": "jwks"`)
	require.Contains(t, got, `"test-key-id"`)
	require.NotContains(t, got, "\x1b[", "JSON output must not contain ANSI escape sequences")

	var unmarshaled map[string]any

	err = json.Unmarshal(payload, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, ResultSchemaVersion, unmarshaled["schemaVersion"])
	require.Equal(t, resultCommand, unmarshaled["command"])
}

func TestResult_JWKSJSON(t *testing.T) {
	t.Parallel()

	res := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
		Keys: []json.RawMessage{
			json.RawMessage(`{"kty":"EC","kid":"ec-key-id","crv":"P-256"}`),
		},
	}

	rawJSON, err := res.JWKSJSON()
	require.NoError(t, err)
	require.Contains(t, rawJSON, `"keys"`)
	require.Contains(t, rawJSON, `"ec-key-id"`)
	require.NotContains(t, rawJSON, "schemaVersion")
	require.NotContains(t, rawJSON, "\x1b[")
}

func TestResult_NilGuards(t *testing.T) {
	t.Parallel()

	_, err := EncodeJSON(nil)
	require.Error(t, err)

	var nilResult *Result

	_, err = nilResult.JWKSJSON()
	require.Error(t, err)
}
