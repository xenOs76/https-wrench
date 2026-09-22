/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package jwtinfo

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// ResultSchemaVersion is the JSON export schema version for jwtinfo results.
	ResultSchemaVersion = "1"
	resultCommand       = "jwtinfo"
)

// Result is the serializable jwtinfo report (source of truth for JSON and console Doc).
type Result struct {
	SchemaVersion string        `json:"schemaVersion"`
	Command       string        `json:"command"`
	AccessToken   *TokenSection `json:"accessToken,omitempty"`
	RefreshToken  *TokenSection `json:"refreshToken,omitempty"`
}

// TokenSection holds plain token metadata for sinks (no ANSI).
type TokenSection struct {
	Valid          *bool           `json:"valid,omitempty"`
	IssuedAt       string          `json:"issuedAt"`
	ExpirationTime string          `json:"expirationTime"`
	Header         json.RawMessage `json:"header"`
	Claims         json.RawMessage `json:"claims"`
}

// BuildResult gathers a serializable report from JwtTokenData. It does not request
// tokens or perform I/O.
func (jtd *JwtTokenData) BuildResult() (*Result, error) {
	if jtd == nil {
		return nil, errors.New("jwtinfo: nil token data")
	}

	r := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
	}

	if len(jtd.AccessTokenHeader) > 0 {
		sec, err := tokenSection(jtd.AccessTokenHeader, jtd.AccessTokenClaims, "AccessToken")
		if err != nil {
			return nil, err
		}

		if jtd.AccessTokenJwt != nil {
			valid := jtd.AccessTokenJwt.Valid
			sec.Valid = &valid
		}

		r.AccessToken = sec
	}

	if len(jtd.RefreshTokenHeader) > 0 {
		sec, err := tokenSection(jtd.RefreshTokenHeader, jtd.RefreshTokenClaims, "RefreshToken")
		if err != nil {
			return nil, err
		}

		if jtd.RefreshTokenJwt != nil {
			valid := jtd.RefreshTokenJwt.Valid
			sec.Valid = &valid
		}

		r.RefreshToken = sec
	}

	return r, nil
}

// EncodeJSON writes the result as indented JSON with no ANSI.
func EncodeJSON(r *Result) ([]byte, error) {
	if r == nil {
		return nil, errors.New("jwtinfo: nil result")
	}

	return json.MarshalIndent(r, "", "  ")
}

// tokenSection builds a TokenSection from header and claims raw JSON bytes.
func tokenSection(header, claims []byte, name string) (*TokenSection, error) {
	timeClaims, err := unmarshalTokenTimeClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal time claims from %s: %w", name, err)
	}

	return &TokenSection{
		IssuedAt:       timeClaims["iat"],
		ExpirationTime: timeClaims["exp"],
		Header:         asRawMessage(header),
		Claims:         asRawMessage(claims),
	}, nil
}

// asRawMessage wraps valid JSON bytes or marshals arbitrary strings into a json.RawMessage.
func asRawMessage(b []byte) json.RawMessage {
	if json.Valid(b) {
		return json.RawMessage(append([]byte(nil), b...))
	}

	enc, err := json.Marshal(string(b))
	if err != nil {
		return json.RawMessage(`""`)
	}

	return enc
}
