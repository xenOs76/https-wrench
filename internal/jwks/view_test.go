package jwks

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func TestBuildDoc_NilResult(t *testing.T) {
	t.Parallel()

	doc := BuildDoc(nil)
	require.Len(t, doc.Nodes, 3)

	var buf bytes.Buffer

	err := view.Render(&buf, doc, view.Options{})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "Jwks")
}

func TestBuildDoc_WithResult(t *testing.T) {
	t.Parallel()

	res := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
		Keys: []json.RawMessage{
			json.RawMessage(`{"kty":"RSA","kid":"key-1"}`),
		},
	}

	doc := BuildDoc(res)
	require.Len(t, doc.Nodes, 4)

	var buf bytes.Buffer

	err := view.Render(&buf, doc, view.Options{})
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "Jwks")
	require.Contains(t, out, `"keys"`)
	require.Contains(t, out, `"key-1"`)
}
