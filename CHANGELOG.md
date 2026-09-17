<!-- markdownlint-disable MD024 -->

# https-wrench - changelog

## 0.16.0 (2026-09-17)

### Dependencies

    Deps: upgrade golang.org/x/sync to v0.23.0 and promote to direct dependency.

### Feat

    Requests: support concurrent HTTP requests execution via bounded worker pool (`--concurrency` / `-c` flag, default: 10).

    Requests: add `concurrency` property to configuration schema and examples, defaulting to 10 if omitted or <= 0.

    Requests: extend concurrency boundaries down to individual single requests, enabling multiple hosts and URIs within a single `RequestConfig` to execute concurrently.

    Requests: bound active host goroutines in `processHostsConcurrently` using `errgroup.Group.SetLimit`, keeping the HTTP request limiter exclusively for URI requests.

    Requests: acquire limiter slot before launching goroutines in `processURIsConcurrently` to eliminate unbounded goroutine allocation.

    Requests: serialize debug output writing (`PrintRequestDebug`, `PrintResponseDebug`) via mutex to eliminate log tearing and data races across concurrent requests.

    Requests: preserve deterministic slice ordering for hosts and URIs, aggregating response data by request name.

### Fix

    Devenv: update profiling cleanup traps to remove generated `requests.test` binary from the invocation directory instead of `internal/requests/requests.test`.

    Devenv: add `EXIT` trap to aggregate profiling script to guarantee test binary cleanup on command failures, and remove redundant test binary cleanup from trace script.

    Schema: remove `minimum: 0` constraint on `concurrency` in both `https-wrench.schema.json` and `internal/mcp/assets/schema.json` so negative values are accepted and fall back cleanly to 10.

### Tests

    Requests: add `TestRequests_ExecuteWithWriter_PeakInFlight` regression test measuring peak in-flight requests with barrier synchronization to eliminate timing jitter under race detection and coverage instrumentation.

    Requests: add `BenchmarkExecuteWithWriter` benchmarking performance across concurrency tiers (`1`, `2`, `5`, `10`, `20`).

    Devenv: add isolated profiling scripts (`profile-requests-concurrency-cpu`, `profile-requests-concurrency-mem`, `profile-requests-concurrency-block`, `profile-requests-concurrency-mutex`, `profile-requests-concurrency-all`, and `trace-requests-concurrency-goroutines`) to avoid measurement cross-talk.

## 0.15.4 (2026-09-15)

### Feat

    MCP: add main requests configuration reference (`assets/examples/https-wrench-mcp-main-config.yaml`) covering all schema options, proxy protocol v2, full certificate chain filtering, and wire debugging against os76.xyz endpoints.

    MCP: expose `https-wrench://main-config` static resource and `https-wrench://examples/mcp-main-config` template, and integrate them into `author_requests_config` prompt hints.

    MCP: update all MCP tool descriptions and parameter schemas to consistently suggest `--format json` CLI examples with standard `path/to/...` placeholders, and default `build_cli_command` to `--format json` output.

    MCP: add rich `jsonschema` parameter annotations to `certinfoInput` and `jwtinfoInput` for agent schema discovery.

### Docs

    MCP: add concrete CLI example to `build_cli_command` tool description.

## 0.15.3 (2026-09-15)

### Dependencies

    MCP: upgrade modelcontextprotocol/go-sdk to v1.8.0.

### Feat

    MCP: recommend `--format json` across MCP server instructions, tools, and cheat-sheet resources for structured machine readability.

    MCP: add dedicated parameterized prompts (`inspect_certificate`, `inspect_jwt`, `generate_jwks`) and reference cheat sheets (`https-wrench://docs/certinfo`, `https-wrench://docs/jwtinfo`, `https-wrench://docs/jwks`) for all diagnostic subcommands.

    Docs: document all MCP prompts and documentation cheat-sheet resources in README.md.

### Fix

    MCP: enforce POSIX single-quote escaping with standard `'"'"'` sequence in `shellQuote` to prevent subshell evaluation of special characters and variable substitutions.

    MCP: preserve supplied `--ca-bundle` and `--tls-info` flags when defaulting to fallback endpoint in `inspect_certificate` prompt flow.

    MCP: replace angle-bracket placeholders with shell-safe file paths in JWKS documentation and prompt examples to avoid shell redirection.

## 0.15.2 (2026-09-14)

### CI

    switch to Go 1.27.1

### Feat

    Certinfo: multi-sink output — typed Result as source of truth, console via internal/view Doc + lipgloss renderer, and `--format json` (schemaVersion, no ANSI). MCP certinfo returns JSON.

    Jwtinfo: multi-sink output — typed Result as source of truth, console via internal/view Doc, and `--format json` (schemaVersion, no ANSI). MCP jwtinfo returns JSON.

    Requests: multi-sink output — typed Result as source of truth, console via internal/view Doc, and `--format json` (schemaVersion, no ANSI). MCP requests returns JSON.

    Jwks: multi-sink output — typed Result as source of truth, console via internal/view Doc, and `--format json` (schemaVersion, no ANSI). MCP generate_jwks returns JSON. Synchronize allowedCLICommands format flag in MCP.


    Requests: add `followRedirects` configuration option (defaulting to false) in JSON schema and Go client to control HTTP 3xx redirection.

    Requests: adopt traffic-light color progression for HTTP status codes (2xx green, 3xx yellow, 4xx peach, 5xx red).

    Requests: pin Go 1.27 ML-KEM hybrid CurvePreferences (including P-521 fallback) and print the negotiated key exchange.

    Jwtinfo: add sentinel and typed errors for errors.Is/As, and route CLI/MCP display through errdisp domain leaves.

    Jwks: add sentinel errors for PEM decode, unsupported key, and non-public key; route CLI display through errdisp.

    Requests: add sentinel and typed errors for client/validation leaves (nil client, empty args, serverName URL, wrong transport, timeout, proxyproto, URI, transport URL).

    Mcp: add sentinel and typed errors for tool-boundary input rules (config/token sources, required fields, TLS info, encrypted key env, validation joins).

    Certinfo: add InvalidTLSEndpointError for host:port parse failures.

    Jwtinfo: add typed errors for base64 JWT parts, JWT parse sources, and invalid request-values JSON.

### Next Steps

    Documentation: Document `--format json` across all diagnostic subcommands (certinfo, jwtinfo, requests, jwks) in README.md.

    Requests: Deprecate legacy imperative `printTLSInfo` in `internal/requests/requests.go` in favor of `internal/requests/view.go` Doc rendering.

    Testing: Expand devenv integration scripts for `certinfo` and `jwtinfo` `--format json` to match `requests` and `jwks`.

### Fix

    Jwks: return error from RunE on unsupported format so command execution exits with status 1.

    Cmd: write JSON output to cmd.OutOrStdout() directly via fmt.Fprintln instead of cmd.Println to ensure payloads go to stdout.

    Requests: gate response body output on `printResponseBody` so configuring `responseBodyMatchRegexp` does not inadvertently dump the response body.

    Requests: reject duplicate request names with DuplicateRequestNameError in ExecuteWithWriter and BuildResult to preserve distinct response data.

    Certinfo: safely handle nil SerialNumber in FromX509.

    Certinfo: read the CA bundle once in SetCaPoolFromFile and derive both CertPool and certificate slice from the same PEM bytes.

    Certinfo: omit protocol/cipher scan sections until ProbeTLSInfo has completed; keep negotiated TLS output when requested.

    Certinfo: propagate cobra cmd.Context() to SetTLSEndpoint and ProbeTLSInfo instead of context.Background().

    Devenv: prefer httpbin on 127.0.0.1:8081 and proxy nginx upstreams through the allocated httpbin port so `devenv test` keeps working when the preferred port is already taken; fail fast in request integration tests with `set -e`, enable `pipefail` on success-case request leaf pipelines, and assert request exit status separately from expected error text.

### Refactor

    Certinfo: collapse styled and plain cert printers onto CertsDoc + view.Render; separate collect from present (cache CA certs, probe TLS before sinks).

    Jwtinfo: separate collect from present onto BuildDoc + view.Render; route `--format json` token persistence and refresh progress to stderr to keep stdout machine-readable.

    Requests: separate HTTP/TLS execution from presentation onto BuildDoc + view.Render; route `--format json` output purely to stdout with debug logs routed to stderr.

    View: centralize Chroma syntax highlighting on Code nodes with line boundary preservation.

### Tests

    Devenv: expand requests test suite to cover all schema settings combinations including responseHeadersFilter, responseCertificatesFilter, request/response debug dumps, baseRequest YAML anchors, userAgent and custom headers, multi-host with default URI fallback, regex matching without body printing, quiet mode, and --format json schema validation.

    Certinfo: assert PrivateKey match label and value together under plain PrintData rendering.

    Certinfo and requests: share CA/leaf certificate generation and custom TLS httptest servers via internal/tlstest.

    Tlstest: close the httptest listener when certificate loading fails.

    Tlstest: leave tls.Config.CipherSuites nil by default and accept only TLS 1.0-1.2 suite overrides.

    Certinfo: GetRemoteCerts tests apply SetTLSInsecure before SetTLSEndpoint so endpoint certificate retrieval uses the intended TLS verification mode.

    Requests: httptest TLS servers bind an ephemeral port so parallel cases do not collide on fixed listeners.

    Cmd: re-bind viper flags after Reset so repeated test counts keep CLI flag bindings.

## 0.15.1 (2026-09-03)

### Feat

    Certinfo: match ML-DSA private keys to certificates and print ML-DSA key type and parameter set. Devenv scripts assert the nginx ML-DSA-65 vhost on localhost:9447.

## 0.15.0 (2026-09-02)

### CI

    switch to Go 1.27.0

### Feat

    Certinfo: add initial support for Post Quantum Key Echange Mechanisms

## 0.14.3 (2026-08-23)

### CI

    update crypto to v0.55.0

## 0.14.2 (2026-08-22)

### CI

    switch to Go 1.26.7

## 0.14.1 (2026-07-22)

### CI

    switch to Go 1.26.5

## 0.14.0 (2026-05-25)

### Feat

    Added an MCP server mode exposed via a new mcp CLI subcommand and shown in CLI help.
    New MCP tools: validate configs, build CLI commands, generate JWKS, run requests, inspect certs and JWTs.
    MCP prompts/resources to generate starter request configs and reference docs.

### Doc

    New/expanded JSON schema, sample config and multiple example YAMLs demonstrating usage and options.

### Fix

    Certificate display now includes IP addresses when filtered.

## 0.13.0 (2026-05-19)

### Feat

    Added selective filtering for TLS certificate chain fields. Users can now control which certificate properties are displayed by index and field name, or leave empty to show all fields.

### Docs

    Added configuration examples demonstrating certificate filtering usage.

## 0.12.1 (2026-05-18)

### Fix

    Fix version injection in Goreleaser config

## 0.12.0 (2026-05-18)

### Feat

    Added --tls-info flag to display negotiated TLS protocol and cipher information from remote endpoints, with probing of supported protocols and cipher suites.

### Docs

    Updated README with expanded certinfo command examples and documentation for the new --tls-info flag.

## 0.11.2 (2026-05-18)

### Fix

    requests: --show-sample-config print to Stdout instead of Strerr.

### Docs

    Updated jwtinfo command help text to display a concrete OIDC provider JWKS discovery URL example instead of a generic placeholder.

## 0.11.1 (2026-05-04)

### Docs

    Reformatted example commands in README with clearer multi-line invocations for better readability.
    Expanded jwtinfo examples to demonstrate combined flag usage.

### Feat

    Enhanced jwtinfo command to support combined request-value flags for greater flexibility.

### Fix

    Added validation requiring --request-url when using --refresh flag.

### CI

    Expanded test coverage with additional scenarios and improved test structure.

## 0.11.0 (2026-05-02)

### Feat

    Automatic token refresh capability—tokens stay fresh in background until expiration
    Save tokens to file with optional background refresh functionality
    Enhanced token lifecycle management with configurable thresholds

### Doc

    Updated usage examples demonstrating token refresh workflows and file persistence features

## 0.10.1 (2026-05-01)

### Refactor

    Improved internal code organization and structure for better maintainability across core modules.

### Chores

    Enhanced code quality tooling with additional linting rules and complexity checks.
    Updated build and development configuration.

### Tests

    Updated test suites to reflect internal code restructuring.

## 0.10.0 (2026-04-29)

### Feat

    Added JWT inspection and validation functionality supporting local files and remote token providers.
    Added JWKS generation from public key files with syntax-highlighted output.

### Doc

    Updated README with JWT/JWKS sections, examples, and sample output images.
    Enhanced command descriptions and help text for clarity.

## 0.9.2 (2026-04-04)

### Feat

- **jwtinfo**: allow reading JWT token from file (#24)

## 0.9.1 (2026-03-26)

### Feat

- add file input option to JwtInfo (#23)

### Refactor

- **jwtinfo**: ParseTokenData function to Parse methods (#22)

## 0.9.0 (2026-03-21)

## 0.8.6 (2025-11-21)

## 0.8.5 (2025-11-17)

### Fix

- **certinfo**: cert and ca file paths display (#6)

## 0.8.4 (2025-11-15)

### Refactor

- HandleRequests function and create processHTTPRequestsByHost (#4)

## 0.8.3 (2025-11-08)

## 0.8.2 (2025-10-17)

### Refactor

- GetKeyFromFile

## 0.8.1 (2025-10-17)

### Refactor

- lint certinfo
- lint cmd
- update rel path to Json schema for test-configs files
- move Certinfo and Requests to internal, move code from src to upper level

## 0.8.0 (2025-10-07)

### Feat

- improve details in Certificate view
- exclude system CA pool when using custom CA Bundle

### Refactor

- remove time globals
- unexport structs
- error format, error variable shadowing
- multiplication of durations
- var naming, unused var
- line length
- deep exit
- unexport error vars
- deep exit
- deep exit
- unecessary conversion
- var naming

## 0.7.0 (2025-09-27)

### Feat

- **certinfo**: read encrypted private keys

## 0.6.0 (2025-09-25)

### Feat

- **certinfo**: add labels to PrintData function
- **requests**: add syntax highlight to response body display

### Fix

- error strings

### Refactor

- **certinfo**: CertsToTable improve readability and add color coded warning on
  cert expiration

## 0.5.0 (2025-09-21)

### Feat

- add certinfo command

## 0.4.0 (2025-09-13)

### Feat

- add responseBodyMatchRegexp option

## 0.3.0 (2025-09-08)

### Feat

- add insecure option

### Fix

- typo in proxyProtoHeaderFromRequest

## 0.2.0 (2025-09-07)

### Feat

- add enableProxyProtocolV2 to request options

## 0.1.0 (2025-09-06)

### Feat

- **json-schema**: add caBundle option to Json schema
- add caBundle option to Yaml configuration

## 0.0.4 (2025-08-29)

## 0.0.3 (2025-08-28)

## 0.0.2 (2025-08-26)

## 0.0.1 (2025-08-16)
