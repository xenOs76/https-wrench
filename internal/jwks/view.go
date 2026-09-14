/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package jwks

import (
	"github.com/xenos76/https-wrench/internal/view"
)

// BuildDoc builds a console view document from a Result.
func BuildDoc(r *Result) view.Doc {
	nodes := []view.Node{
		view.Blank{},
		view.Banner{Text: "Jwks"},
		view.Blank{},
	}

	if r == nil {
		return view.Doc{Nodes: nodes}
	}

	body, err := r.JWKSJSON()
	if err != nil {
		body = "{}"
	}

	nodes = append(nodes, view.Code{Lang: "json", Body: body})

	return view.Doc{Nodes: nodes}
}
