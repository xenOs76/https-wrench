package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestShellQuote(t *testing.T) {
	t.Parallel()

	require.Equal(t, "''", shellQuote(""))
	require.Equal(t, "plain", shellQuote("plain"))
	require.Equal(t, `"has space"`, shellQuote("has space"))
	require.Equal(t, `"say \"hi\""`, shellQuote(`say "hi"`))
}

func TestParsePaths(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"/"}, parsePaths(""))
	require.Equal(t, []string{"/a", "/b"}, parsePaths(" /a , /b "))
	require.Equal(t, []string{"/"}, parsePaths(" , , "))
}

func TestLoadConfigYAML(t *testing.T) {
	t.Parallel()

	_, err := loadConfigYAML("", "")
	require.Error(t, err)

	_, err = loadConfigYAML("a: 1", "/tmp/x.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "exactly one")

	yaml, err := loadConfigYAML("verbose: true\n", "")
	require.NoError(t, err)
	require.Contains(t, yaml, "verbose")

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	require.NoError(t, os.WriteFile(path, []byte("verbose: true\n"), 0o600))

	yaml, err = loadConfigYAML("", path)
	require.NoError(t, err)
	require.Contains(t, yaml, "verbose")

	_, err = loadConfigYAML("", filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "read config file")
}

func TestValidateRequestsConfig_errors(t *testing.T) {
	t.Parallel()

	valid, errs := validateRequestsConfig("not: [valid: yaml")
	require.False(t, valid)
	require.NotEmpty(t, errs)

	valid, errs = validateRequestsConfig("verbose: true\nrequests: not-a-list\n")
	require.False(t, valid)
	require.NotEmpty(t, errs)

	valid, errs = validateRequestsConfig(`verbose: true
requests:
  - name: x
    transportOverrideUrl: http://bad
    hosts:
      - name: h
        uriList:
          - /
`)
	require.False(t, valid)
	require.Contains(t, strings.Join(errs, " "), "https://")

	valid, errs = validateRequestsConfig(`verbose: true
requests:
  - name: x
    enableProxyProtocolV2: true
    hosts:
      - name: h
        uriList:
          - /
`)
	require.False(t, valid)
	require.Contains(t, strings.Join(errs, " "), "enableProxyProtocolV2")

	valid, errs = validateRequestsConfig(`verbose: true
requests:
  - name: ""
    hosts: []
`)
	require.False(t, valid)
	require.NotEmpty(t, errs)
}

func TestBuildRequestsConfigYAML_errors(t *testing.T) {
	t.Parallel()

	_, errs := buildRequestsConfigYAML(requestsConfigTemplateInput{})
	require.NotEmpty(t, errs)

	_, errs = buildRequestsConfigYAML(requestsConfigTemplateInput{
		Hostname: "app.example.com",
		Paths:    "no-slash",
	})
	require.NotEmpty(t, errs)
}

func TestBuildCLICommand(t *testing.T) {
	t.Parallel()

	_, errs := buildCLICommand("unknown", nil)
	require.NotEmpty(t, errs)

	cmd, errs := buildCLICommand("jwks", map[string]string{
		"public-key-file": "/keys/pub.pem",
		"kid":             "my-kid",
	})
	require.Empty(t, errs)
	require.Contains(t, cmd, "https-wrench jwks")

	_, errs = buildCLICommand("jwtinfo", map[string]string{"token-file": "t.jwt"})
	require.Empty(t, errs)

	_, errs = buildCLICommand("requests", map[string]string{"config": "cfg.yaml"})
	require.Empty(t, errs)

	_, errs = buildCLICommand("certinfo", map[string]string{"unknown-flag": "x"})
	require.NotEmpty(t, errs)

	_, errs = buildCLICommand("jwtinfo", map[string]string{})
	require.NotEmpty(t, errs)
}

func TestExecToolTimeout(t *testing.T) {
	t.Parallel()

	require.Equal(t, defaultExecToolTimeout, execToolTimeout(0))
	require.Equal(t, 5*time.Second, execToolTimeout(5))
}

func TestCertinfoInputProvided(t *testing.T) {
	t.Parallel()

	require.False(t, certinfoInputProvided(certinfoInput{}))
	require.True(t, certinfoInputProvided(certinfoInput{CertBundle: "x.pem"}))
}

func TestLoadJwtTokenData_errors(t *testing.T) {
	t.Parallel()

	_, err := loadJwtTokenData(context.Background(), jwtinfoInput{})
	require.Error(t, err)

	_, err = loadJwtTokenData(context.Background(), jwtinfoInput{
		TokenFile:  "a.jwt",
		RequestURL: "https://example.com/token",
	})
	require.Error(t, err)

	_, err = loadJwtTokenData(context.Background(), jwtinfoInput{
		RequestURL: "https://example.com/token",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "requestValues")
}

func TestCaptureOutput_error(t *testing.T) {
	t.Parallel()

	_, err := captureOutput(func(_ io.Writer) error {
		return errors.New("boom")
	})
	require.Error(t, err)
}

func TestExampleResourceHints(t *testing.T) {
	t.Parallel()

	hints := exampleResourceHints(requestsConfigTemplateInput{Hostname: "app.example.com"})
	require.Contains(t, hints, "k3s")

	hints = exampleResourceHints(requestsConfigTemplateInput{
		Hostname:             "app.example.com",
		TransportOverrideURL: "https://edge.example.net",
	})
	require.Contains(t, hints, "proxy-protocol-v2")

	hints = exampleResourceHints(requestsConfigTemplateInput{
		Hostname: "app.example.com",
		Insecure: true,
	})
	require.Contains(t, hints, "k3s")
}

func TestAuthorRequestsConfigPrompt_insecureAndErrors(t *testing.T) {
	t.Parallel()

	_, err := authorRequestsConfigPrompt(context.Background(), &sdkmcp.GetPromptRequest{
		Params: &sdkmcp.GetPromptParams{Arguments: map[string]string{}},
	})
	require.Error(t, err)

	res, err := authorRequestsConfigPrompt(context.Background(), &sdkmcp.GetPromptRequest{
		Params: &sdkmcp.GetPromptParams{Arguments: map[string]string{
			"hostname": "app.example.com",
			"insecure": "true",
		}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Messages)
}

func TestReadExampleResource_notFound(t *testing.T) {
	t.Parallel()

	_, err := readExampleResource(context.Background(), &sdkmcp.ReadResourceRequest{
		Params: &sdkmcp.ReadResourceParams{URI: "https-wrench://examples/"},
	})
	require.Error(t, err)

	_, err = readExampleResource(context.Background(), &sdkmcp.ReadResourceRequest{
		Params: &sdkmcp.ReadResourceParams{URI: "https-wrench://examples/unknown-example"},
	})
	require.Error(t, err)
}

func TestTextResource(t *testing.T) {
	t.Parallel()

	res := textResource("https-wrench://test", "hello")
	require.Equal(t, "hello", res.Contents[0].Text)
}

func TestNewServer_emptyVersion(t *testing.T) {
	t.Parallel()

	server := NewServer("")
	require.NotNil(t, server)
}

func TestExecuteHelpers(t *testing.T) {
	t.Parallel()

	_, err := executeCertinfo(context.Background(), certinfoInput{})
	require.Error(t, err)

	_, err = executeCertinfo(context.Background(), certinfoInput{
		TLSEndpoint:   "example.com:443",
		TLSInsecure:   true,
		TLSInfo:       true,
		TLSServername: "example.com",
	})
	require.NoError(t, err)

	_, err = executeGenerateJWKS(context.Background(), generateJWKSInput{})
	require.Error(t, err)

	_, err = executeRunRequests(context.Background(), runRequestsInput{})
	require.Error(t, err)

	_, err = executeJwtinfo(context.Background(), jwtinfoInput{TokenFile: "/no/such/token.jwt"})
	require.Error(t, err)
}

func TestLoadRequestsConfigYAML_invalid(t *testing.T) {
	t.Parallel()

	_, _, err := loadRequestsConfigYAML("requests: [")
	require.Error(t, err)

	_, _, err = loadRequestsConfigYAML("verbose: true\nrequests: not-a-list\n")
	require.Error(t, err)
}

func TestBuildRequestsMetaConfig_caBundle(t *testing.T) {
	t.Parallel()

	pubFile := filepath.Join("..", "certinfo", "testdata", "rsa-pkcs8-crt.pem")
	loaded := loadedRequestsConfig{Verbose: true}

	meta, err := buildRequestsMetaConfig(loaded, pubFile)
	require.NoError(t, err)
	require.NotNil(t, meta)
}

func TestJwtinfoHandler_requestURL(t *testing.T) {
	t.Parallel()

	tokenString := writeTestJWT(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + tokenString + `"}`))
	}))
	t.Cleanup(ts.Close)

	out, err := executeJwtinfo(context.Background(), jwtinfoInput{
		RequestURL:    ts.URL,
		RequestValues: map[string]string{"grant_type": "client_credentials"},
	})
	require.NoError(t, err)
	require.Contains(t, out.Output, "JwtInfo")
}

func TestRequestsConfigTemplateHandler_error(t *testing.T) {
	t.Parallel()

	_, _, err := requestsConfigTemplateHandler(
		context.Background(),
		nil,
		requestsConfigTemplateInput{},
	)
	require.Error(t, err)
}

func TestMCPFileReader(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")
	require.NoError(t, os.WriteFile(path, []byte("ok"), 0o600))

	reader := mcpFileReader{}
	data, err := reader.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "ok", string(data))
	require.True(t, reader.NoPasswordPrompt())

	_, err = reader.ReadPassword(0)
	require.Error(t, err)
}

func writeTestJWT(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   "mcp-test",
	})

	tokenString, err := token.SignedString(priv)
	require.NoError(t, err)

	return tokenString
}
