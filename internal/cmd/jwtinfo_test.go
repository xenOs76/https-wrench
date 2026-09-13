package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
)

func TestJwtinfoCmd_Errors(t *testing.T) {
	tests := []struct {
		name     string
		setup    func()
		expected []string
	}{
		{
			name: "invalid file",
			setup: func() {
				tokenFile = "non_existent.jwt"
			},
			expected: []string{"error while reading token value from file"},
		},
		{
			name: "refresh without request url",
			setup: func() {
				tokenFile = "some.jwt"
				refresh = true
				requestURL = ""
			},
			expected: []string{"Error: --refresh requires --request-url"},
		},
		{
			name: "unsupported format",
			setup: func() {
				tokenFile = "some.jwt"
				jwtinfoFmt = "yaml"
			},
			expected: []string{"Error: unsupported --format \"yaml\" (use text or json)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetFlags()
			tt.setup()

			out := new(bytes.Buffer)
			jwtinfoCmd.SetOut(out)
			jwtinfoCmd.SetErr(out)
			jwtinfoCmd.SetContext(context.Background())

			jwtinfoCmd.Run(jwtinfoCmd, nil)

			got := out.String()
			for _, expected := range tt.expected {
				require.Contains(t, got, expected)
			}
		})
	}
}

func TestJwtinfoCmd_Success(t *testing.T) {
	// Mock Token Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// JWT Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1516249022}
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2M" +
			"jM5MDIyLCJleHAiOjE1MTYyNDkwMjJ9.c2lnbmF0dXJl"
		_, _ = w.Write([]byte(`{"access_token": "` + token + `"}`))
	}))
	defer ts.Close()

	t.Run("default text format", func(t *testing.T) {
		resetFlags()

		requestURL = ts.URL
		requestSteps = []requestValueStep{{kind: "kv", value: "key=val"}}

		out := new(bytes.Buffer)
		jwtinfoCmd.SetOut(out)
		jwtinfoCmd.SetErr(out)
		jwtinfoCmd.SetContext(context.Background())

		jwtinfoCmd.Run(jwtinfoCmd, nil)

		got := out.String()
		require.Contains(t, got, "JwtInfo")
		require.Contains(t, got, "AccessToken")
		require.Contains(t, got, "\"sub\"")
		require.Contains(t, got, "\"1234567890\"")
	})

	t.Run("json format", func(t *testing.T) {
		resetFlags()

		requestURL = ts.URL
		requestSteps = []requestValueStep{{kind: "kv", value: "key=val"}}
		jwtinfoFmt = "json"

		out := new(bytes.Buffer)
		jwtinfoCmd.SetOut(out)
		jwtinfoCmd.SetErr(out)
		jwtinfoCmd.SetContext(context.Background())

		jwtinfoCmd.Run(jwtinfoCmd, nil)

		got := out.String()
		require.NotContains(t, got, "\x1b[")

		var res jwtinfo.Result
		require.NoError(t, json.Unmarshal(out.Bytes(), &res))
		require.Equal(t, jwtinfo.ResultSchemaVersion, res.SchemaVersion)
		require.Equal(t, "jwtinfo", res.Command)
		require.NotNil(t, res.AccessToken)
		require.Contains(t, string(res.AccessToken.Claims), "1234567890")
	})
}

func resetFlags() {
	jwtinfoCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
		f.Value.Set(f.DefValue)
	})

	requestSteps = nil
	tokenFile = ""
	requestURL = ""
	refresh = false
	jwksURL = ""
	tokenOutputFile = ""
	renewThreshold = 80.0
	jwtinfoFmt = "text"
}
