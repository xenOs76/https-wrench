package mcp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	mcpserver "github.com/xenos76/https-wrench/internal/mcp"
)

func TestGenerateJwksTool(t *testing.T) {
	t.Parallel()

	pubFile := writeRSAPublicKeyPEM(t)

	out := callExecTool(t, "generate_jwks", map[string]any{
		"publicKeyFile": pubFile,
	})
	require.Empty(t, out["error"])
	require.Contains(t, out["output"], `"keys"`)
}

func TestCertinfoTool_localBundle(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "certinfo", map[string]any{
		"certBundle": filepath.Join("..", "certinfo", "testdata", "rsa-pkcs8-crt.pem"),
	})
	require.Empty(t, out["error"])
	require.Contains(t, out["output"], "Certinfo")
}

func TestCertinfoTool_encryptedKeyNoPassword(t *testing.T) {
	t.Setenv("CERTINFO_PKEY_PW", "")

	out := callExecTool(t, "certinfo", map[string]any{
		"keyFile": filepath.Join("..", "certinfo", "testdata", "rsa-pkcs8-encrypted-private-key.pem"),
	})
	require.NotEmpty(t, out["error"])
	require.Contains(t, out["error"], "CERTINFO_PKEY_PW")
}

func TestJwtinfoTool_tokenFile(t *testing.T) {
	t.Parallel()

	tokenFile := writeJWTTokenFile(t)

	out := callExecTool(t, "jwtinfo", map[string]any{
		"tokenFile": tokenFile,
	})
	require.Empty(t, out["error"])
	require.Contains(t, out["output"], "JwtInfo")
}

func TestRunRequestsTool_invalidConfig(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "run_requests", map[string]any{
		"configYaml": "requests:\n  - name: x\n    hosts:\n      - name: example.com\n",
	})
	require.NotEmpty(t, out["error"])
	require.Contains(t, out["error"], "verbose")
}

func TestRunRequestsTool_configPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "requests.yaml")
	yaml := `verbose: true
requests:
  - name: from-file
    requestMethod: HEAD
    hosts:
      - name: example.com
        uriList:
          - /
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))

	out := callExecTool(t, "run_requests", map[string]any{
		"configPath": cfgPath,
	})
	require.Empty(t, out["error"])
	require.Contains(t, out["output"], "from-file")
}

func TestRunRequestsTool_bothConfigSources(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "run_requests", map[string]any{
		"configYaml": "verbose: true",
		"configPath": "/tmp/x.yaml",
	})
	require.NotEmpty(t, out["error"])
	require.Contains(t, out["error"], "exactly one")
}

func TestCertinfoTool_noInput(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "certinfo", map[string]any{})
	require.NotEmpty(t, out["error"])
}

func TestCertinfoTool_tlsInfoRequiresEndpoint(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "certinfo", map[string]any{
		"certBundle": filepath.Join("..", "certinfo", "testdata", "rsa-pkcs8-crt.pem"),
		"tlsInfo":    true,
	})
	require.NotEmpty(t, out["error"])
	require.Contains(t, out["error"], "tlsInfo requires tlsEndpoint")
}

func TestGenerateJwksTool_missingFile(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "generate_jwks", map[string]any{
		"publicKeyFile": "",
	})
	require.NotEmpty(t, out["error"])
}

func TestJwtinfoTool_invalidToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jwt")
	require.NoError(t, os.WriteFile(path, []byte("not-a-jwt"), 0o600))

	out := callExecTool(t, "jwtinfo", map[string]any{
		"tokenFile": path,
	})
	require.NotEmpty(t, out["error"])
}

func TestRunRequestsTool_invalidCaBundle(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "run_requests", map[string]any{
		"configYaml": `verbose: true
caBundle: "not-a-pem-bundle"
requests:
  - name: bad-ca
    requestMethod: HEAD
    hosts:
      - name: example.com
        uriList:
          - /
`,
	})
	require.NotEmpty(t, out["error"])
}

func TestRunRequestsTool_invalidCaBundlePath(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "run_requests", map[string]any{
		"configYaml": `verbose: true
requests:
  - name: bad-ca-path
    requestMethod: HEAD
    hosts:
      - name: example.com
        uriList:
          - /
`,
		"caBundlePath": filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	require.NotEmpty(t, out["error"])
}

func TestJwtinfoTool_emptyAccessToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jwt")
	require.NoError(t, os.WriteFile(path, []byte(`{"access_token":""}`), 0o600))

	out := callExecTool(t, "jwtinfo", map[string]any{
		"tokenFile": path,
	})
	require.NotEmpty(t, out["error"])
}

func TestCertinfoTool_invalidCertBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a cert"), 0o600))

	out := callExecTool(t, "certinfo", map[string]any{
		"certBundle": path,
	})
	require.NotEmpty(t, out["error"])
}

func TestCertinfoTool_invalidCaBundle(t *testing.T) {
	t.Parallel()

	out := callExecTool(t, "certinfo", map[string]any{
		"caBundle": filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	require.NotEmpty(t, out["error"])
}

func TestBuildCLICommand_jwtinfo(t *testing.T) {
	t.Parallel()

	out := callBuildCLITool(t, map[string]any{
		"command": "jwtinfo",
		"flags": map[string]any{
			"token-file": "token.jwt",
		},
	})
	require.Empty(t, out["errors"])
	require.Contains(t, out["command"], "jwtinfo")
}

func TestBuildCLICommand_requests(t *testing.T) {
	t.Parallel()

	out := callBuildCLITool(t, map[string]any{
		"command": "requests",
		"flags": map[string]any{
			"show-sample-config": "true",
		},
	})
	require.Empty(t, out["errors"])
	require.Contains(t, out["command"], "requests")
}

func TestResources_readDocs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.ReadResource(ctx, &sdkmcp.ReadResourceParams{
		URI: "https-wrench://docs/requests",
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Contents)
	require.Contains(t, res.Contents[0].Text, "requests")
}

func TestResources_readSampleConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.ReadResource(ctx, &sdkmcp.ReadResourceParams{
		URI: "https-wrench://sample-config",
	})
	require.NoError(t, err)
	require.Contains(t, res.Contents[0].Text, "requests:")
}

func TestValidateRequestsConfig_invalidYAML(t *testing.T) {
	t.Parallel()

	out := callValidateTool(t, "verbose: true\nrequests: [")
	require.False(t, out["valid"].(bool))
}

func TestRunRequestsTool_inlineYaml(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(httpHandlerOK())
	t.Cleanup(ts.Close)

	hostPort := ts.Listener.Addr().String()
	yaml := `verbose: true
requests:
  - name: mcp-test
    requestMethod: GET
    insecure: true
    transportOverrideUrl: https://` + hostPort + `
    printResponseBody: true
    hosts:
      - name: example.com
        uriList:
          - /
`

	out := callExecTool(t, "run_requests", map[string]any{
		"configYaml": yaml,
	})
	require.Empty(t, out["error"])
	require.Contains(t, out["output"], "mcp-test")
}

func callExecTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()

	ctx := context.Background()
	session, cleanup, err := mcpserver.RunInMemory(ctx, "test")
	require.NoError(t, err)

	defer cleanup()

	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	return decodeStructuredOutput(t, res)
}

func writeRSAPublicKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "rsa-public.pem")
	file, err := os.Create(path)
	require.NoError(t, err)

	err = pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	require.NoError(t, err)
	require.NoError(t, file.Close())

	return path
}

func writeJWTTokenFile(t *testing.T) string {
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

	path := filepath.Join(t.TempDir(), "token.jwt")
	require.NoError(t, os.WriteFile(path, []byte(tokenString), 0o600))

	return path
}

func httpHandlerOK() http.Handler {
	return httpHandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

func (f httpHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}
