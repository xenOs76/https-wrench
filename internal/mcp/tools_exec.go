package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/jwks"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
	"github.com/xenos76/https-wrench/internal/requests"
)

const (
	defaultExecToolTimeout = 60 * time.Second
	certinfoKeyPasswordEnv = "CERTINFO_PKEY_PW"
)

// execToolOutput encapsulates JSON payload text and any error message from execution tools.
type execToolOutput struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// runRequestsInput specifies inline YAML or a file path to execute requests against.
type runRequestsInput struct {
	ConfigYAML   string `json:"configYaml,omitempty" jsonschema:"Inline requests YAML configuration"`
	ConfigPath   string `json:"configPath,omitempty" jsonschema:"Path to requests YAML on the MCP server host"`
	CaBundlePath string `json:"caBundlePath,omitempty" jsonschema:"Optional CA bundle PEM file path"`
	TimeoutSec   int    `json:"timeoutSec,omitempty" jsonschema:"Overall operation timeout in seconds (default 60)"`
}

// certinfoInput holds parameters for certificate, private key, or TLS endpoint inspection.
type certinfoInput struct {
	CaBundle      string `json:"caBundle,omitempty" jsonschema:"Optional CA bundle PEM file path"`
	CertBundle    string `json:"certBundle,omitempty" jsonschema:"PEM certificate bundle file path"`
	KeyFile       string `json:"keyFile,omitempty" jsonschema:"PEM key path (use CERTINFO_PKEY_PW env)"`
	TLSEndpoint   string `json:"tlsEndpoint,omitempty" jsonschema:"TLS endpoint host:port"`
	TLSServername string `json:"tlsServername,omitempty" jsonschema:"Optional SNI server name"`
	TLSInsecure   bool   `json:"tlsInsecure,omitempty" jsonschema:"Skip TLS certificate verification"`
	TLSInfo       bool   `json:"tlsInfo,omitempty" jsonschema:"Probe negotiated and supported TLS info"`
	TimeoutSec    int    `json:"timeoutSec,omitempty" jsonschema:"Timeout in seconds (default 60)"`
}

// jwtinfoInput holds parameters for parsing, verifying, or fetching a JWT token.
type jwtinfoInput struct {
	TokenFile     string            `json:"tokenFile,omitempty" jsonschema:"File path containing JWT token string"`
	RequestURL    string            `json:"requestUrl,omitempty" jsonschema:"OAuth/OIDC token endpoint URL"`
	RequestValues map[string]string `json:"requestValues,omitempty" jsonschema:"Key-value pairs for token request"`
	ValidationURL string            `json:"validationUrl,omitempty" jsonschema:"Remote JWKS URL for verification"`
	TimeoutSec    int               `json:"timeoutSec,omitempty" jsonschema:"Timeout in seconds (default 60)"`
}

// generateJWKSInput specifies a public key file and key ID to construct a JWKS.
type generateJWKSInput struct {
	PublicKeyFile string `json:"publicKeyFile" jsonschema:"Path to PEM-encoded public key file"`
	Kid           string `json:"kid,omitempty" jsonschema:"Optional key ID"`
}

// loadedRequestsConfig holds unmarshaled requests configuration and execution options.
type loadedRequestsConfig struct {
	Debug    bool
	Verbose  bool
	CaBundle string
	Requests []requests.RequestConfig
}

// mcpFileReader implements file reading and non-interactive password retrieval for MCP.
type mcpFileReader struct{}

// ReadFile reads the named file from the filesystem.
func (mcpFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// NoPasswordPrompt indicates that interactive password prompts are disabled.
func (mcpFileReader) NoPasswordPrompt() bool { return true }

// ReadPassword returns an error because interactive terminal prompts are unsupported in MCP.
func (mcpFileReader) ReadPassword(_ int) ([]byte, error) {
	return nil, ErrEncryptedKeyNeedsEnv
}

// registerExecTools registers execution-capable tools on the given MCP server.
func registerExecTools(server *sdkmcp.Server) {
	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name: "run_requests",
		Description: "Execute https-wrench requests from inline YAML or a config file path " +
			"(returns JSON; CLI: https-wrench requests --config path/to/file.yaml --format json)",
	}, runRequestsHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name: "certinfo",
		Description: "Inspect x.509 certificates and keys from local files or a TLS endpoint " +
			"(returns JSON; CLI: https-wrench certinfo --tls-endpoint example.com:443 --format json)",
	}, certinfoHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name: "jwtinfo",
		Description: "Inspect JWT tokens from a file or token endpoint (no refresh loop) " +
			"(returns JSON; CLI: https-wrench jwtinfo --token-file path/to/token.jwt --format json)",
	}, jwtinfoHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name: "generate_jwks",
		Description: "Generate a JSON Web Key Set from a PEM public key file " +
			"(returns JSON; CLI: https-wrench jwks --public-key-file path/to/public.pem --format json)",
	}, generateJWKSHandler)
}

// runRequestsHandler executes the run_requests MCP tool.
func runRequestsHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input runRequestsInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeRunRequests(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: errdisp.Format(err)}, nil
	}

	return nil, out, nil
}

// certinfoHandler executes the certinfo MCP tool.
func certinfoHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input certinfoInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeCertinfo(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: errdisp.Format(err)}, nil
	}

	return nil, out, nil
}

// jwtinfoHandler executes the jwtinfo MCP tool.
func jwtinfoHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input jwtinfoInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeJwtinfo(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: errdisp.Format(err)}, nil
	}

	return nil, out, nil
}

// generateJWKSHandler executes the generate_jwks MCP tool.
func generateJWKSHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input generateJWKSInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, 0)
	defer cancel()

	out, err := executeGenerateJWKS(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: errdisp.Format(err)}, nil
	}

	return nil, out, nil
}

// executeRunRequests executes requests within the provided context.
func executeRunRequests(ctx context.Context, input runRequestsInput) (execToolOutput, error) {
	return runWithContext(ctx, func(ctx context.Context) (execToolOutput, error) {
		if err := ctx.Err(); err != nil {
			return execToolOutput{}, err
		}

		return runRequestsExec(ctx, input)
	})
}

// runRequestsExec validates, parses, and executes the requests configuration.
func runRequestsExec(ctx context.Context, input runRequestsInput) (execToolOutput, error) {
	if err := ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	yamlContent, err := loadConfigYAML(input.ConfigYAML, input.ConfigPath)
	if err != nil {
		return execToolOutput{}, err
	}

	valid, errs := validateRequestsConfig(yamlContent)
	if !valid {
		return execToolOutput{}, &ValidationError{Messages: errs, Prefixed: true}
	}

	loaded, _, err := loadRequestsConfigYAML(yamlContent)
	if err != nil {
		return execToolOutput{}, err
	}

	meta, err := buildRequestsMetaConfig(loaded, input.CaBundlePath)
	if err != nil {
		return execToolOutput{}, err
	}

	result, _, err := meta.Execute(ctx)
	if err != nil {
		return execToolOutput{}, err
	}

	return requestsJSONOutput(result)
}

// requestsJSONOutput serializes requests results to JSON formatted tool output.
func requestsJSONOutput(result *requests.Result) (execToolOutput, error) {
	payload, err := requests.EncodeJSON(result)
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: string(payload)}, nil
}

// executeCertinfo runs certificate and TLS endpoint inspection within the provided context.
func executeCertinfo(ctx context.Context, input certinfoInput) (execToolOutput, error) {
	return runWithContext(ctx, func(ctx context.Context) (execToolOutput, error) {
		if err := ctx.Err(); err != nil {
			return execToolOutput{}, err
		}

		return certinfoExec(ctx, input)
	})
}

// certinfoExec configures the certinfo inspector, probes targets, and builds the result.
func certinfoExec(ctx context.Context, input certinfoInput) (execToolOutput, error) {
	if err := ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	if !certinfoInputProvided(input) {
		return execToolOutput{}, ErrCertinfoInputRequired
	}

	if input.TLSInfo && input.TLSEndpoint == "" {
		return execToolOutput{}, ErrTLSInfoNeedsEndpoint
	}

	cfg, err := certinfo.New()
	if err != nil {
		return execToolOutput{}, err
	}

	reader := mcpFileReader{}

	if err = ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	if err = cfg.SetCaPoolFromFile(input.CaBundle, reader); err != nil {
		return execToolOutput{}, err
	}

	if err = cfg.SetCertsFromFile(input.CertBundle, reader); err != nil {
		return execToolOutput{}, err
	}

	if err = ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	cfg.SetTLSInsecure(input.TLSInsecure).
		SetTLSServerName(input.TLSServername).
		SetTLSInfoRequested(input.TLSInfo)

	if err = cfg.SetTLSEndpoint(ctx, input.TLSEndpoint); err != nil {
		return execToolOutput{}, err
	}

	if err = ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	if err = cfg.SetPrivateKeyFromFile(input.KeyFile, certinfoKeyPasswordEnv, reader); err != nil {
		return execToolOutput{}, err
	}

	if input.TLSInfo {
		if err = cfg.ProbeTLSInfo(ctx); err != nil {
			return execToolOutput{}, err
		}
	}

	return certinfoJSONOutput(cfg)
}

// certinfoJSONOutput encodes certinfo results into JSON formatted tool output.
func certinfoJSONOutput(cfg *certinfo.Config) (execToolOutput, error) {
	result, err := cfg.BuildResult()
	if err != nil {
		return execToolOutput{}, err
	}

	payload, err := certinfo.EncodeJSON(result)
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: string(payload)}, nil
}

// executeJwtinfo loads and parses JWT token data within the provided context.
func executeJwtinfo(ctx context.Context, input jwtinfoInput) (execToolOutput, error) {
	tokenData, err := loadJwtTokenData(ctx, input)
	if err != nil {
		return execToolOutput{}, err
	}

	if tokenData == nil || tokenData.AccessTokenRaw == "" {
		return execToolOutput{}, ErrNoJWTTokenData
	}

	if err = tokenData.DecodeBase64(); err != nil {
		return execToolOutput{}, err
	}

	if input.ValidationURL != "" {
		if err = tokenData.ParseWithJWKS(ctx, input.ValidationURL, keyfunc.Override{}); err != nil {
			return execToolOutput{}, err
		}
	}

	return jwtinfoJSONOutput(tokenData)
}

// jwtinfoJSONOutput serializes JWT analysis results into JSON formatted tool output.
func jwtinfoJSONOutput(tokenData *jwtinfo.JwtTokenData) (execToolOutput, error) {
	result, err := tokenData.BuildResult()
	if err != nil {
		return execToolOutput{}, err
	}

	payload, err := jwtinfo.EncodeJSON(result)
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: string(payload)}, nil
}

// executeGenerateJWKS loads a public key and generates a JWKS JSON tool output.
func executeGenerateJWKS(ctx context.Context, input generateJWKSInput) (execToolOutput, error) {
	if strings.TrimSpace(input.PublicKeyFile) == "" {
		return execToolOutput{}, &RequiredFieldError{Field: "publicKeyFile"}
	}

	result, err := jwks.Generate(ctx, input.PublicKeyFile, input.Kid)
	if err != nil {
		return execToolOutput{}, err
	}

	payload, err := jwks.EncodeJSON(result)
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: string(payload)}, nil
}

// loadConfigYAML retrieves configuration content from inline YAML or a local file path.
func loadConfigYAML(configYAML, configPath string) (string, error) {
	hasYAML := strings.TrimSpace(configYAML) != ""
	hasPath := strings.TrimSpace(configPath) != ""

	switch {
	case hasYAML && hasPath:
		return "", ErrExactlyOneConfigSource
	case !hasYAML && !hasPath:
		return "", ErrConfigSourceRequired
	case hasPath:
		data, err := os.ReadFile(configPath)
		if err != nil {
			return "", fmt.Errorf("read config file: %w", err)
		}

		return string(data), nil
	default:
		return configYAML, nil
	}
}

// loadRequestsConfigYAML parses requests YAML content and unmarshals it into loadedRequestsConfig.
func loadRequestsConfigYAML(yamlContent string) (loadedRequestsConfig, bool, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(strings.NewReader(yamlContent)); err != nil {
		return loadedRequestsConfig{}, false, fmt.Errorf("yaml parse: %w", err)
	}

	cfg := struct {
		Debug                       bool   `mapstructure:"debug"`
		Verbose                     bool   `mapstructure:"verbose"`
		CaBundle                    string `mapstructure:"caBundle"`
		requests.RequestsMetaConfig `mapstructure:",squash"`
	}{}

	if err := v.Unmarshal(&cfg); err != nil {
		return loadedRequestsConfig{}, false, fmt.Errorf("config unmarshal: %w", err)
	}

	return loadedRequestsConfig{
		Debug:    cfg.Debug,
		Verbose:  cfg.Verbose,
		CaBundle: cfg.CaBundle,
		Requests: cfg.Requests,
	}, v.IsSet("verbose"), nil
}

// buildRequestsMetaConfig constructs and configures a RequestsMetaConfig from loaded options.
func buildRequestsMetaConfig(loaded loadedRequestsConfig, caBundlePath string) (*requests.RequestsMetaConfig, error) {
	meta, err := requests.NewRequestsMetaConfig()
	if err != nil {
		return nil, err
	}

	meta.SetVerbose(loaded.Verbose).
		SetDebug(loaded.Debug).
		SetRequests(loaded.Requests)

	if err = meta.SetCaPoolFromYAML(loaded.CaBundle); err != nil {
		return nil, err
	}

	if err = meta.SetCaPoolFromFile(caBundlePath, mcpFileReader{}); err != nil {
		return nil, err
	}

	return meta, nil
}

// loadJwtTokenData obtains JWT token data either by reading a file or performing an HTTP request.
func loadJwtTokenData(ctx context.Context, input jwtinfoInput) (*jwtinfo.JwtTokenData, error) {
	hasFile := strings.TrimSpace(input.TokenFile) != ""
	hasURL := strings.TrimSpace(input.RequestURL) != ""

	switch {
	case hasFile && hasURL:
		return nil, ErrExactlyOneTokenSource
	case !hasFile && !hasURL:
		return nil, ErrTokenSourceRequired
	case hasFile:
		return jwtinfo.ReadTokenFromFile(input.TokenFile)
	default:
		if len(input.RequestValues) == 0 {
			return nil, &RequiredFieldError{Field: "requestValues"}
		}

		client := &http.Client{Timeout: execToolTimeout(input.TimeoutSec)}

		return jwtinfo.RequestToken(ctx, input.RequestURL, input.RequestValues, client, io.ReadAll)
	}
}

// certinfoInputProvided returns true if at least one certificate or TLS input was provided.
func certinfoInputProvided(input certinfoInput) bool {
	return input.CaBundle != "" ||
		input.CertBundle != "" ||
		input.KeyFile != "" ||
		input.TLSEndpoint != ""
}

// toolContext wraps parent with a timeout derived from timeoutSec.
func toolContext(parent context.Context, timeoutSec int) (context.Context, context.CancelFunc) {
	timeout := execToolTimeout(timeoutSec)

	return context.WithTimeout(parent, timeout)
}

// execToolTimeout converts a timeout in seconds to a Duration, falling back to the default.
func execToolTimeout(timeoutSec int) time.Duration {
	if timeoutSec <= 0 {
		return defaultExecToolTimeout
	}

	return time.Duration(timeoutSec) * time.Second
}

// captureOutput runs fn while capturing standard output to a string.
func captureOutput(fn func(io.Writer) error) (string, error) {
	var buf bytes.Buffer

	if err := fn(&buf); err != nil {
		return buf.String(), err
	}

	return buf.String(), nil
}

// runWithContext executes fn in a goroutine, aborting if ctx expires before completion.
func runWithContext[T any](ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan struct {
		v   T
		err error
	}, 1)

	go func() {
		v, err := fn(ctx)
		done <- struct {
			v   T
			err error
		}{v: v, err: err}
	}()

	select {
	case <-ctx.Done():
		var zero T

		return zero, ctx.Err()
	case r := <-done:
		return r.v, r.err
	}
}
