# https-wrench - changelog

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
