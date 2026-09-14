/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package jwks

import (
	"encoding/json"
	"errors"
)

const (
	// ResultSchemaVersion is the JSON export schema version for jwks results.
	ResultSchemaVersion = "1"
	resultCommand       = "jwks"
)

// Result is the serializable jwks report (source of truth for JSON and console Doc).
type Result struct {
	SchemaVersion string            `json:"schemaVersion"`
	Command       string            `json:"command"`
	Keys          []json.RawMessage `json:"keys"`
}

// EncodeJSON writes the result as indented JSON with no ANSI.
func EncodeJSON(r *Result) ([]byte, error) {
	if r == nil {
		return nil, errors.New("jwks: nil result")
	}

	return json.MarshalIndent(r, "", "  ")
}

// JWKSJSON returns the standard RFC 7517 JWK Set JSON ({"keys": [...]})
// pretty-printed without the tool result envelope.
func (r *Result) JWKSJSON() (string, error) {
	if r == nil {
		return "", errors.New("jwks: nil result")
	}

	raw := struct {
		Keys []json.RawMessage `json:"keys"`
	}{
		Keys: r.Keys,
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
