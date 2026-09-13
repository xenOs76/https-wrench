/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package view

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRender_Plain(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Banner{Text: "Certinfo"},
		Blank{},
		Section{
			Title: "PrivateKey",
			Level: 1,
			Kids: []Node{
				KV{Key: "PrivateKey file", Value: "/tmp/key.pem"},
				Table{Rows: [][]Cell{
					{{Text: "Type", Tone: ToneKey}, {Text: "RSA", Tone: ToneValue}},
				}},
			},
		},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{Plain: true}))

	got := buf.String()
	require.Contains(t, got, "Certinfo")
	require.Contains(t, got, "PrivateKey")
	require.Contains(t, got, "PrivateKey file: /tmp/key.pem")
	require.Contains(t, got, "Type")
	require.Contains(t, got, "RSA")
	require.NotContains(t, got, "\x1b[")
}

func TestRender_ForceColor(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Banner{Text: "Certinfo"},
		KV{Key: "match", Value: "true", Tone: ToneBoolTrue},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))
	require.Contains(t, buf.String(), "Certinfo")
}

func TestRender_Code_Plain(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Code{Lang: "json", Body: `{"alg":"RS256"}`},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{Plain: true}))

	got := buf.String()
	require.Contains(t, got, `"alg":"RS256"`)
	require.NotContains(t, got, "\x1b[")
}

func TestRender_Code_ForceColor(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Code{Lang: "json", Body: `{"alg":"RS256"}`},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))

	got := buf.String()
	require.Contains(t, got, "RS256")
	require.Contains(t, got, "\x1b[")
}
