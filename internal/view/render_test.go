/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package view

import (
	"bytes"
	"os"
	"strings"
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
				Table{
					Headers: []string{"Col1", "Col2"},
					Rows: [][]Cell{
						{{Text: "Type", Tone: ToneKey}, {Text: "RSA", Tone: ToneValue}},
					},
				},
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
	require.True(t, strings.HasSuffix(got, "\n"))
	require.False(t, strings.HasSuffix(got, "\n\n"))
}

func TestRender_StatusTones_ForceColor(t *testing.T) {
	t.Parallel()

	tones := []Tone{ToneStatus2xx, ToneStatus3xx, ToneStatus4xx, ToneStatus5xx}
	for _, tone := range tones {
		doc := Doc{Nodes: []Node{
			KV{Key: "StatusCode", Value: "test", Tone: tone},
		}}

		var buf bytes.Buffer
		require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))

		got := buf.String()
		require.Contains(t, got, "StatusCode")
		require.Contains(t, got, "test")
	}
}

func TestRender_Table_Styled(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Table{
			Headers: []string{"Header1", "Header2"},
			Rows: [][]Cell{
				{
					{Text: "Row1Col1", Tone: ToneDefault},
					{Text: "Row1Col2", Tone: ToneDefault},
				},
				{
					{Text: "Row2Col1", Tone: ToneKey},
					{Text: "Row2Col2", Tone: ToneWarn},
				},
			},
		},
		Table{
			Rows: [][]Cell{
				{
					{Text: "SingleRowCol1", Tone: ToneCrit},
					{Text: "SingleRowCol2", Tone: ToneBoolTrue},
				},
			},
		},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))

	got := buf.String()
	require.Contains(t, got, "Header1")
	require.Contains(t, got, "Header2")
	require.Contains(t, got, "Row1Col1")
	require.Contains(t, got, "Row1Col2")
	require.Contains(t, got, "SingleRowCol1")
}

func TestRender_AllTones_ForceColor(t *testing.T) {
	t.Parallel()

	allTones := []Tone{
		ToneDefault,
		ToneKey,
		ToneValue,
		ToneWarn,
		ToneCrit,
		ToneBoolTrue,
		ToneBoolFalse,
		ToneNotice,
		ToneURL,
		ToneCmd,
		ToneSection,
		ToneHeader,
		ToneStatus2xx,
		ToneStatus3xx,
		ToneStatus4xx,
		ToneStatus5xx,
		Tone(9999), // default fallback
	}

	for _, tone := range allTones {
		doc := Doc{Nodes: []Node{
			KV{Key: "Key", Value: "Val", Tone: tone},
		}}

		var buf bytes.Buffer
		require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))
		require.Contains(t, buf.String(), "Key")
		require.Contains(t, buf.String(), "Val")
	}
}

// TestRender_IsTerminalAndFile verifies rendering behavior when target writer is a non-terminal *os.File.
func TestRender_IsTerminalAndFile(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	defer r.Close()
	defer w.Close()

	doc := Doc{Nodes: []Node{
		Banner{Text: "FileBanner"},
	}}

	// Writing to an os.File without ForceColor (pipe is not a TTY)
	require.NoError(t, Render(w, doc, Options{Plain: false, ForceColor: false}))
}

func TestViewNodes_Markers(t *testing.T) {
	t.Parallel()

	// Invoke marker method on all concrete node types
	Banner{}.viewNode()
	Blank{}.viewNode()
	Section{}.viewNode()
	KV{}.viewNode()
	Table{}.viewNode()
	Code{}.viewNode()
}

func TestRender_SectionLevels(t *testing.T) {
	t.Parallel()

	doc := Doc{Nodes: []Node{
		Section{Level: 0, Title: "Level 0", Kids: []Node{KV{Key: "K0", Value: "V0"}}},
		Section{Level: 1, Title: "Level 1", Kids: []Node{KV{Key: "K1", Value: "V1"}}},
		Section{Level: 2, Title: "Level 2", Kids: []Node{KV{Key: "K2", Value: "V2"}}},
		Section{Level: 3, Title: "Level 3", Kids: []Node{KV{Key: "K3", Value: "V3"}}},
	}}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, doc, Options{ForceColor: true}))

	got := buf.String()
	require.Contains(t, got, "Level 0")
	require.Contains(t, got, "Level 1")
	require.Contains(t, got, "Level 2")
	require.Contains(t, got, "Level 3")
}
