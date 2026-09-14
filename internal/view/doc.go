/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

// Package view is a small visual outcome model for CLI console sinks.
// Domain packages build a Doc; Render owns lipgloss/theme application.
package view

// Tone selects semantic coloring at paint time (never stored as ANSI).
type Tone int

const (
	// ToneDefault is the default key/value appearance.
	ToneDefault Tone = iota
	// ToneWarn marks near-expiration or cautionary values.
	ToneWarn
	// ToneCrit marks expired or critical values.
	ToneCrit
	// ToneBoolTrue styles affirmative booleans.
	ToneBoolTrue
	// ToneBoolFalse styles negative booleans.
	ToneBoolFalse
	// ToneNotice highlights secondary cert metadata (e.g. IsCA, key IDs).
	ToneNotice
	// ToneURL styles URLs and endpoints.
	ToneURL
	// ToneCmd styles the command banner.
	ToneCmd
	// ToneSection styles top-level section titles.
	ToneSection
	// ToneKey styles table/KV keys.
	ToneKey
	// ToneValue styles ordinary values.
	ToneValue
	// ToneHeader styles table column headers.
	ToneHeader
	// ToneStatus2xx styles 2xx HTTP status codes (success).
	ToneStatus2xx
	// ToneStatus3xx styles 3xx HTTP status codes (redirection).
	ToneStatus3xx
	// ToneStatus4xx styles 4xx HTTP status codes (client error).
	ToneStatus4xx
	// ToneStatus5xx styles 5xx HTTP status codes (server error).
	ToneStatus5xx
)

// Node is a view document node.
type Node interface {
	viewNode()
}

// Doc is a sequence of view nodes to render.
type Doc struct {
	Nodes []Node
}

// Section is a titled group of child nodes. Level replaces padding-as-type-name styles.
type Section struct {
	Title string
	Level int
	Kids  []Node
}

func (Section) viewNode() {}

// KV is a key/value line with an optional value tone.
type KV struct {
	Key, Value string
	Tone       Tone
}

func (KV) viewNode() {}
