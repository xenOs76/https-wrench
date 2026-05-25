package mcp

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/xenos76/https-wrench/internal/jwks"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
	"github.com/xenos76/https-wrench/internal/requests"
)

const (
	defaultExecToolTimeout = 60 * time.Second
	certinfoKeyPasswordEnv = "CERTINFO_PKEY_PW"
)

type execToolOutput struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

type runRequestsInput struct {
	ConfigYAML   string `json:"configYaml,omitempty" jsonschema:"Inline requests YAML configuration"`
	ConfigPath   string `json:"configPath,omitempty" jsonschema:"Path to requests YAML on the MCP server host"`
	CaBundlePath string `json:"caBundlePath,omitempty" jsonschema:"Optional CA bundle PEM file path"`
	TimeoutSec   int    `json:"timeoutSec,omitempty" jsonschema:"Overall operation timeout in seconds (default 60)"`
}

type certinfoInput struct {
	CaBundle      string `json:"caBundle,omitempty"`
	CertBundle    string `json:"certBundle,omitempty"`
	KeyFile       string `json:"keyFile,omitempty"`
	TLSEndpoint   string `json:"tlsEndpoint,omitempty"`
	TLSServername string `json:"tlsServername,omitempty"`
	TLSInsecure   bool   `json:"tlsInsecure,omitempty"`
	TLSInfo       bool   `json:"tlsInfo,omitempty"`
	TimeoutSec    int    `json:"timeoutSec,omitempty"`
}

type jwtinfoInput struct {
	TokenFile     string            `json:"tokenFile,omitempty"`
	RequestURL    string            `json:"requestUrl,omitempty"`
	RequestValues map[string]string `json:"requestValues,omitempty"`
	ValidationURL string            `json:"validationUrl,omitempty"`
	TimeoutSec    int               `json:"timeoutSec,omitempty"`
}

type generateJWKSInput struct {
	PublicKeyFile string `json:"publicKeyFile" jsonschema:"Path to PEM-encoded public key file"`
	Kid           string `json:"kid,omitempty" jsonschema:"Optional key ID"`
}

type loadedRequestsConfig struct {
	Debug    bool
	Verbose  bool
	CaBundle string
	Requests []requests.RequestConfig
}

type mcpFileReader struct{}

func (mcpFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (mcpFileReader) NoPasswordPrompt() bool { return true }

func (mcpFileReader) ReadPassword(_ int) ([]byte, error) {
	return nil, errors.New("encrypted private keys require CERTINFO_PKEY_PW under MCP")
}

func registerExecTools(server *sdkmcp.Server) {
	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "run_requests",
		Description: "Execute https-wrench requests from inline YAML or a config file path",
	}, runRequestsHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "certinfo",
		Description: "Inspect x.509 certificates and keys from local files or a TLS endpoint",
	}, certinfoHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "jwtinfo",
		Description: "Inspect JWT tokens from a file or token endpoint (no refresh loop)",
	}, jwtinfoHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "generate_jwks",
		Description: "Generate a JSON Web Key Set from a PEM public key file",
	}, generateJWKSHandler)
}

func runRequestsHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input runRequestsInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeRunRequests(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: err.Error()}, nil
	}

	return nil, out, nil
}

func certinfoHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input certinfoInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeCertinfo(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: err.Error()}, nil
	}

	return nil, out, nil
}

func jwtinfoHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input jwtinfoInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, input.TimeoutSec)
	defer cancel()

	out, err := executeJwtinfo(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: err.Error()}, nil
	}

	return nil, out, nil
}

func generateJWKSHandler(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	input generateJWKSInput,
) (*sdkmcp.CallToolResult, execToolOutput, error) {
	ctx, cancel := toolContext(ctx, 0)
	defer cancel()

	out, err := executeGenerateJWKS(ctx, input)
	if err != nil {
		return nil, execToolOutput{Error: err.Error()}, nil
	}

	return nil, out, nil
}

func executeRunRequests(ctx context.Context, input runRequestsInput) (execToolOutput, error) {
	return runWithContext(ctx, func(ctx context.Context) (execToolOutput, error) {
		if err := ctx.Err(); err != nil {
			return execToolOutput{}, err
		}

		return runRequestsExec(ctx, input)
	})
}

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
		return execToolOutput{}, fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}

	loaded, _, err := loadRequestsConfigYAML(yamlContent)
	if err != nil {
		return execToolOutput{}, err
	}

	meta, err := buildRequestsMetaConfig(loaded, input.CaBundlePath)
	if err != nil {
		return execToolOutput{}, err
	}

	output, err := captureOutput(func(w io.Writer) error {
		_, handleErr := requests.HandleRequests(ctx, w, meta)

		return handleErr
	})
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: output}, nil
}

func executeCertinfo(ctx context.Context, input certinfoInput) (execToolOutput, error) {
	return runWithContext(ctx, func(ctx context.Context) (execToolOutput, error) {
		if err := ctx.Err(); err != nil {
			return execToolOutput{}, err
		}

		return certinfoExec(ctx, input)
	})
}

func certinfoExec(ctx context.Context, input certinfoInput) (execToolOutput, error) {
	if err := ctx.Err(); err != nil {
		return execToolOutput{}, err
	}

	if !certinfoInputProvided(input) {
		return execToolOutput{}, errors.New(
			"one of tlsEndpoint, certBundle, keyFile, or caBundle is required",
		)
	}

	if input.TLSInfo && input.TLSEndpoint == "" {
		return execToolOutput{}, errors.New("tlsInfo requires tlsEndpoint")
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

	output, err := captureOutput(func(w io.Writer) error {
		return cfg.PrintData(ctx, w)
	})
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: output}, nil
}

func executeJwtinfo(ctx context.Context, input jwtinfoInput) (execToolOutput, error) {
	tokenData, err := loadJwtTokenData(ctx, input)
	if err != nil {
		return execToolOutput{}, err
	}

	if tokenData == nil || tokenData.AccessTokenRaw == "" {
		return execToolOutput{}, errors.New("no JWT token data available")
	}

	if err = tokenData.DecodeBase64(); err != nil {
		return execToolOutput{}, err
	}

	if input.ValidationURL != "" {
		if err = tokenData.ParseWithJWKS(ctx, input.ValidationURL, keyfunc.Override{}); err != nil {
			return execToolOutput{}, err
		}
	}

	output, err := captureOutput(func(w io.Writer) error {
		return jwtinfo.PrintTokenInfo(tokenData, w)
	})
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: output}, nil
}

func executeGenerateJWKS(ctx context.Context, input generateJWKSInput) (execToolOutput, error) {
	if strings.TrimSpace(input.PublicKeyFile) == "" {
		return execToolOutput{}, errors.New("publicKeyFile is required")
	}

	jwksJSON, err := jwks.GenerateJWKS(ctx, input.PublicKeyFile, input.Kid)
	if err != nil {
		return execToolOutput{}, err
	}

	return execToolOutput{Output: jwksJSON}, nil
}

func loadConfigYAML(configYAML, configPath string) (string, error) {
	hasYAML := strings.TrimSpace(configYAML) != ""
	hasPath := strings.TrimSpace(configPath) != ""

	switch {
	case hasYAML && hasPath:
		return "", errors.New("provide exactly one of configYaml or configPath")
	case !hasYAML && !hasPath:
		return "", errors.New("configYaml or configPath is required")
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

func loadJwtTokenData(ctx context.Context, input jwtinfoInput) (*jwtinfo.JwtTokenData, error) {
	hasFile := strings.TrimSpace(input.TokenFile) != ""
	hasURL := strings.TrimSpace(input.RequestURL) != ""

	switch {
	case hasFile && hasURL:
		return nil, errors.New("provide exactly one of tokenFile or requestUrl")
	case !hasFile && !hasURL:
		return nil, errors.New("tokenFile or requestUrl is required")
	case hasFile:
		return jwtinfo.ReadTokenFromFile(input.TokenFile)
	default:
		if len(input.RequestValues) == 0 {
			return nil, errors.New("requestValues is required with requestUrl")
		}

		client := &http.Client{Timeout: execToolTimeout(input.TimeoutSec)}

		return jwtinfo.RequestToken(ctx, input.RequestURL, input.RequestValues, client, io.ReadAll)
	}
}

func certinfoInputProvided(input certinfoInput) bool {
	return input.CaBundle != "" ||
		input.CertBundle != "" ||
		input.KeyFile != "" ||
		input.TLSEndpoint != ""
}

func toolContext(parent context.Context, timeoutSec int) (context.Context, context.CancelFunc) {
	timeout := execToolTimeout(timeoutSec)

	return context.WithTimeout(parent, timeout)
}

func execToolTimeout(timeoutSec int) time.Duration {
	if timeoutSec <= 0 {
		return defaultExecToolTimeout
	}

	return time.Duration(timeoutSec) * time.Second
}

func captureOutput(fn func(io.Writer) error) (string, error) {
	var buf bytes.Buffer

	if err := fn(&buf); err != nil {
		return buf.String(), err
	}

	return buf.String(), nil
}

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
