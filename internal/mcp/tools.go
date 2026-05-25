package mcp

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/requests"
)

type validateRequestsConfigInput struct {
	ConfigYAML string `json:"configYaml" jsonschema:"YAML content of a https-wrench requests configuration file"`
}

type validateRequestsConfigOutput struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

type requestsConfigTemplateInput struct {
	Hostname             string `json:"hostname" jsonschema:"Application hostname (hosts[].name)"`
	Paths                string `json:"paths,omitempty" jsonschema:"Comma-separated URI paths starting with /"`
	TransportOverrideURL string `json:"transportOverrideUrl,omitempty" jsonschema:"Optional https:// dial URL"`
	Insecure             bool   `json:"insecure,omitempty" jsonschema:"Set insecure true on the request"`
	Method               string `json:"method,omitempty" jsonschema:"HTTP method (default HEAD)"`
	RequestName          string `json:"requestName,omitempty" jsonschema:"Display name for the request entry"`
}

type requestsConfigTemplateOutput struct {
	ConfigYAML string `json:"configYaml"`
}

type buildCLICommandInput struct {
	Command string            `json:"command" jsonschema:"Subcommand: certinfo, jwtinfo, jwks, or requests"`
	Flags   map[string]string `json:"flags" jsonschema:"Flag names (without leading dashes) to values"`
}

type buildCLICommandOutput struct {
	Command string   `json:"command"`
	Errors  []string `json:"errors,omitempty"`
}

type cliCommandDef struct {
	requiredFlags []string
	oneOfGroups   [][]string
	allowedFlags  map[string]struct{}
}

type parsedRequestsConfig struct {
	Verbose  bool
	Requests []requests.RequestConfig
}

func registerTools(server *sdkmcp.Server) {
	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "validate_requests_config",
		Description: "Parse and structurally validate a https-wrench requests YAML configuration",
	}, validateRequestsConfigHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "requests_config_template",
		Description: "Generate a starter requests YAML configuration from high-level parameters",
	}, requestsConfigTemplateHandler)

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "build_cli_command",
		Description: "Build a shell-ready https-wrench CLI command for certinfo, jwtinfo, jwks, or requests",
	}, buildCLICommandHandler)

	registerExecTools(server)
}

func validateRequestsConfigHandler(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	input validateRequestsConfigInput,
) (*sdkmcp.CallToolResult, validateRequestsConfigOutput, error) {
	valid, errs := validateRequestsConfig(input.ConfigYAML)

	return nil, validateRequestsConfigOutput{Valid: valid, Errors: errs}, nil
}

func requestsConfigTemplateHandler(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	input requestsConfigTemplateInput,
) (*sdkmcp.CallToolResult, requestsConfigTemplateOutput, error) {
	yaml, errs := buildRequestsConfigYAML(input)
	if len(errs) > 0 {
		return nil, requestsConfigTemplateOutput{}, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil, requestsConfigTemplateOutput{ConfigYAML: yaml}, nil
}

func buildCLICommandHandler(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	input buildCLICommandInput,
) (*sdkmcp.CallToolResult, buildCLICommandOutput, error) {
	cmd, errs := buildCLICommand(input.Command, input.Flags)

	out := buildCLICommandOutput{Command: cmd, Errors: errs}
	if len(errs) > 0 {
		return nil, out, nil
	}

	return nil, out, nil
}

func validateRequestsConfig(yamlContent string) (bool, []string) {
	cfg, verboseSet, err := parseRequestsConfigYAML(yamlContent)
	if err != nil {
		return false, []string{err.Error()}
	}

	var errs []string

	if !verboseSet {
		errs = append(errs, "verbose is required")
	}

	if len(cfg.Requests) == 0 {
		errs = append(errs, "requests must contain at least one entry")
	}

	for i, req := range cfg.Requests {
		errs = append(errs, validateRequestConfig(i, req)...)
	}

	return len(errs) == 0, errs
}

func parseRequestsConfigYAML(yamlContent string) (parsedRequestsConfig, bool, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(strings.NewReader(yamlContent)); err != nil {
		return parsedRequestsConfig{}, false, fmt.Errorf("yaml parse: %w", err)
	}

	cfg := struct {
		Verbose                     bool `mapstructure:"verbose"`
		requests.RequestsMetaConfig `mapstructure:",squash"`
	}{}

	if err := v.Unmarshal(&cfg); err != nil {
		return parsedRequestsConfig{}, false, fmt.Errorf("config unmarshal: %w", err)
	}

	return parsedRequestsConfig{
		Verbose:  cfg.Verbose,
		Requests: cfg.Requests,
	}, v.IsSet("verbose"), nil
}

func validateRequestConfig(index int, req requests.RequestConfig) []string {
	prefix := fmt.Sprintf("requests[%d]", index)

	var errs []string

	if req.Name == "" {
		errs = append(errs, prefix+": name is required")
	}

	if len(req.Hosts) == 0 {
		errs = append(errs, prefix+": hosts must be non-empty")
	}

	if req.TransportOverrideURL != "" && !strings.HasPrefix(req.TransportOverrideURL, "https://") {
		errs = append(errs, prefix+": transportOverrideUrl must start with https://")
	}

	if req.EnableProxyProtocolV2 && req.TransportOverrideURL == "" {
		errs = append(errs, prefix+": enableProxyProtocolV2 requires transportOverrideUrl")
	}

	for hi, host := range req.Hosts {
		errs = append(errs, validateRequestHost(prefix, hi, host)...)
	}

	return errs
}

func validateRequestHost(prefix string, index int, host requests.Host) []string {
	hostPrefix := fmt.Sprintf("%s.hosts[%d]", prefix, index)

	var errs []string

	if host.Name == "" {
		errs = append(errs, hostPrefix+": name is required")
	}

	for ui, uri := range host.URIList {
		if !uri.Parse() {
			errs = append(errs, fmt.Sprintf("%s.uriList[%d]: path %q must start with /", hostPrefix, ui, uri))
		}
	}

	return errs
}

func buildRequestsConfigYAML(input requestsConfigTemplateInput) (string, []string) {
	var errs []string

	hostname := strings.TrimSpace(input.Hostname)
	if hostname == "" {
		errs = append(errs, "hostname is required")
	}

	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = "HEAD"
	}

	name := strings.TrimSpace(input.RequestName)
	if name == "" {
		name = "example-" + strings.ReplaceAll(hostname, ".", "-")
	}

	paths := parsePaths(input.Paths)

	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			errs = append(errs, fmt.Sprintf("path %q must start with /", p))
		}
	}

	if len(errs) > 0 {
		return "", errs
	}

	var b strings.Builder
	fmt.Fprintln(&b, schemaCommentHeader)
	fmt.Fprintln(&b, "---")
	fmt.Fprintln(&b, "verbose: true")
	fmt.Fprintln(&b, "requests:")
	fmt.Fprintf(&b, "  - name: %s\n", name)
	fmt.Fprintf(&b, "    requestMethod: %s\n", method)

	if transport := strings.TrimSpace(input.TransportOverrideURL); transport != "" {
		fmt.Fprintf(&b, "    transportOverrideUrl: %s\n", transport)
	}

	if input.Insecure {
		fmt.Fprintln(&b, "    insecure: true")
	}

	fmt.Fprintln(&b, "    hosts:")
	fmt.Fprintf(&b, "      - name: %s\n", hostname)
	fmt.Fprintln(&b, "        uriList:")

	for _, p := range paths {
		fmt.Fprintf(&b, "          - %s\n", p)
	}

	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func parsePaths(paths string) []string {
	paths = strings.TrimSpace(paths)
	if paths == "" {
		return []string{"/"}
	}

	parts := strings.Split(paths, ",")

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	if len(out) == 0 {
		return []string{"/"}
	}

	return out
}

var allowedCLICommands = map[string]cliCommandDef{
	"certinfo": {
		oneOfGroups: [][]string{{"tls-endpoint", "cert-bundle", "key-file", "ca-bundle"}},
		allowedFlags: map[string]struct{}{
			"ca-bundle": {}, "cert-bundle": {}, "key-file": {},
			"tls-endpoint": {}, "tls-servername": {}, "tls-insecure": {}, "tls-info": {},
		},
	},
	"jwtinfo": {
		oneOfGroups: [][]string{{"token-file", "request-url"}},
		allowedFlags: map[string]struct{}{
			"token-file": {}, "request-url": {}, "request-values": {},
			"request-values-json": {}, "request-values-file": {},
			"validation-url": {}, "refresh": {}, "token-output-file": {}, "renew-threshold": {},
		},
	},
	"jwks": {
		requiredFlags: []string{"public-key-file"},
		allowedFlags: map[string]struct{}{
			"public-key-file": {}, "kid": {},
		},
	},
	"requests": {
		oneOfGroups: [][]string{{"config", "show-sample-config"}},
		allowedFlags: map[string]struct{}{
			"config": {}, "show-sample-config": {}, "ca-bundle": {},
		},
	},
}

func buildCLICommand(command string, flags map[string]string) (string, []string) {
	command = strings.ToLower(strings.TrimSpace(command))

	def, ok := allowedCLICommands[command]
	if !ok {
		return "", []string{
			fmt.Sprintf("unsupported command %q (use certinfo, jwtinfo, jwks, or requests)", command),
		}
	}

	errs := validateCLIFlags(command, def, flags)
	if len(errs) > 0 {
		return "", errs
	}

	names := sortedAllowedFlagNames(def, flags)

	var parts []string

	parts = append(parts, "https-wrench", command)
	for _, name := range names {
		parts = append(parts, "--"+name, shellQuote(flags[name]))
	}

	return strings.Join(parts, " "), nil
}

func validateCLIFlags(command string, def cliCommandDef, flags map[string]string) []string {
	var errs []string

	for _, req := range def.requiredFlags {
		if _, set := flags[req]; !set {
			errs = append(errs, fmt.Sprintf("missing required flag %q", req))
		}
	}

	for _, group := range def.oneOfGroups {
		if !oneOfFlagsSet(group, flags) {
			errs = append(errs, fmt.Sprintf("one of flags %v is required", group))
		}
	}

	for name := range flags {
		if _, allowed := def.allowedFlags[name]; !allowed {
			errs = append(errs, fmt.Sprintf("unknown flag %q for command %q", name, command))
		}
	}

	return errs
}

func oneOfFlagsSet(group []string, flags map[string]string) bool {
	for _, name := range group {
		if _, set := flags[name]; set {
			return true
		}
	}

	return false
}

func sortedAllowedFlagNames(def cliCommandDef, flags map[string]string) []string {
	names := make([]string, 0, len(flags))
	for name := range flags {
		if _, allowed := def.allowedFlags[name]; allowed {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}

	if !strings.ContainsAny(value, " \t\n\"'\\$`!#&|;<>()*?[]{}~") {
		return value
	}

	return strconv.Quote(value)
}
