/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package jwtinfo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func TestBuildResult_EncodeJSON(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	exp := now + 3600
	header := []byte(`{"alg":"RS256","typ":"JWT"}`)
	claims := []byte(fmt.Sprintf(`{"iat":%d,"exp":%d,"sub":"demo"}`, now, exp))

	jtd := &JwtTokenData{
		AccessTokenHeader: header,
		AccessTokenClaims: claims,
	}

	result, err := jtd.BuildResult()
	require.NoError(t, err)
	require.Equal(t, ResultSchemaVersion, result.SchemaVersion)
	require.Equal(t, "jwtinfo", result.Command)
	require.NotNil(t, result.AccessToken)
	require.Nil(t, result.AccessToken.Valid)
	require.Nil(t, result.RefreshToken)
	require.Equal(t, "demo", mustClaim(t, result.AccessToken.Claims, "sub"))

	payload, err := EncodeJSON(result)
	require.NoError(t, err)
	require.NotContains(t, string(payload), "\x1b[")

	var decoded Result
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, ResultSchemaVersion, decoded.SchemaVersion)
	require.Equal(t, "jwtinfo", decoded.Command)
	require.NotNil(t, decoded.AccessToken)
	require.Contains(t, string(decoded.AccessToken.Header), "RS256")
}

func TestBuildResult_ValidWhenParsed(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	exp := now + 3600
	jtd := &JwtTokenData{
		AccessTokenHeader:  []byte(`{"alg":"RS256","typ":"JWT"}`),
		AccessTokenClaims:  []byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, now, exp)),
		AccessTokenJwt:     &jwt.Token{Valid: true},
		RefreshTokenHeader: []byte(`{"alg":"HS256","typ":"JWT"}`),
		RefreshTokenClaims: []byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, now, exp)),
		RefreshTokenJwt:    &jwt.Token{Valid: true},
	}

	result, err := jtd.BuildResult()
	require.NoError(t, err)
	require.NotNil(t, result.AccessToken.Valid)
	require.True(t, *result.AccessToken.Valid)
	require.NotNil(t, result.RefreshToken.Valid)
	require.True(t, *result.RefreshToken.Valid)
}

func TestBuildDoc_PlainHasNoANSI(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	exp := now + 3600
	jtd := &JwtTokenData{
		AccessTokenHeader: []byte(`{"alg":"RS256","typ":"JWT"}`),
		AccessTokenClaims: []byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, now, exp)),
		AccessTokenJwt:    &jwt.Token{Valid: true},
	}

	var buf bytes.Buffer
	require.NoError(t, PrintTokenInfoWithOptions(jtd, &buf, view.Options{Plain: true}))

	got := buf.String()
	require.Contains(t, got, "JwtInfo")
	require.Contains(t, got, "AccessToken")
	require.Contains(t, got, "Valid")
	require.Contains(t, got, "Issued At")
	require.Contains(t, got, "Expiration Time")
	require.Contains(t, got, "Header")
	require.Contains(t, got, "Claims")
	require.Contains(t, got, "RS256")
	require.NotContains(t, got, "\x1b[")
}

func TestEncodeJSON_NilResult(t *testing.T) {
	t.Parallel()

	_, err := EncodeJSON(nil)
	require.Error(t, err)
}

func mustClaim(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	v, ok := m[key].(string)
	require.True(t, ok)

	return v
}
