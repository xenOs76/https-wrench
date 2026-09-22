/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package jwtinfo

import (
	"bytes"
	"encoding/json"

	"github.com/xenos76/https-wrench/internal/view"
)

// BuildDoc builds a console view document from a Result.
func BuildDoc(r *Result) view.Doc {
	nodes := []view.Node{
		view.Blank{},
		view.Banner{Text: "JwtInfo"},
		view.Blank{},
	}

	if r == nil {
		return view.Doc{Nodes: nodes}
	}

	if r.AccessToken != nil {
		nodes = append(nodes, tokenSectionDoc("AccessToken", r.AccessToken)...)
	}

	if r.RefreshToken != nil {
		nodes = append(nodes, tokenSectionDoc("RefreshToken", r.RefreshToken)...)
	}

	return view.Doc{Nodes: nodes}
}

// tokenSectionDoc constructs a styled Section node for an AccessToken or RefreshToken.
func tokenSectionDoc(name string, sec *TokenSection) []view.Node {
	kids := make([]view.Node, 0, 8)

	if sec.Valid != nil {
		tone := view.ToneBoolFalse
		val := "false"

		if *sec.Valid {
			tone = view.ToneBoolTrue
			val = "true"
		}

		kids = append(kids, view.KV{Key: "Valid", Value: val, Tone: tone})
	}

	kids = append(kids,
		view.Section{
			Title: "Header",
			Level: 2,
			Kids: []view.Node{
				view.Code{Lang: "json", Body: prettyJSON(sec.Header)},
			},
		},
		view.Section{
			Title: "Claims",
			Level: 2,
			Kids: []view.Node{
				view.Table{
					Rows: [][]view.Cell{
						{
							{Text: "Issued At", Tone: view.ToneKey},
							{Text: sec.IssuedAt, Tone: view.ToneValue},
						},
						{
							{Text: "Expiration Time", Tone: view.ToneKey},
							{Text: sec.ExpirationTime, Tone: view.ToneValue},
						},
					},
				},
				view.Code{Lang: "json", Body: prettyJSON(sec.Claims)},
			},
		},
	)

	return []view.Node{
		view.Section{Title: name, Level: 1, Kids: kids},
	}
}

// prettyJSON formats raw JSON with two-space indentation, falling back to raw string on error.
func prettyJSON(raw json.RawMessage) string {
	var buf bytes.Buffer

	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}

	return buf.String()
}
