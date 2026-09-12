//nolint:revive // max-public-structs: typed domain errors for errors.Is/As
package mcp

import (
	"errors"
	"fmt"
	"strings"
)

// Package-level sentinels for stable MCP tool-boundary failure conditions.
// Match them with errors.Is after wrapping; Error() strings stay human-facing.
var (
	ErrExactlyOneConfigSource = errors.New("provide exactly one of configYaml or configPath")
	ErrConfigSourceRequired   = errors.New("configYaml or configPath is required")
	ErrExactlyOneTokenSource  = errors.New("provide exactly one of tokenFile or requestUrl")
	ErrTokenSourceRequired    = errors.New("tokenFile or requestUrl is required")
	ErrRequestValuesRequired  = errors.New("requestValues is required with requestUrl")
	ErrPublicKeyFileRequired  = errors.New("publicKeyFile is required")
	ErrCertinfoInputRequired  = errors.New(
		"one of tlsEndpoint, certBundle, keyFile, or caBundle is required",
	)
	ErrTLSInfoNeedsEndpoint = errors.New("tlsInfo requires tlsEndpoint")
	ErrEncryptedKeyNeedsEnv = errors.New(
		"encrypted private keys require CERTINFO_PKEY_PW under MCP",
	)
	ErrNoJWTTokenData = errors.New("no JWT token data available")
	ErrInvalidConfig  = errors.New("invalid config")
	ErrValidation     = errors.New("validation failed")
)

// ValidationError collects one or more validation messages.
// errors.Is(err, ErrValidation) is true; ErrInvalidConfig when Prefixed.
type ValidationError struct {
	Messages []string
	Prefixed bool // when true, Error() is "invalid config: ..."
}

// Error returns the joined validation messages.
func (e *ValidationError) Error() string {
	joined := strings.Join(e.Messages, "; ")
	if e.Prefixed {
		return "invalid config: " + joined
	}

	return joined
}

// Is reports whether target is ErrValidation or ErrInvalidConfig when Prefixed.
func (e *ValidationError) Is(target error) bool {
	if target == ErrValidation {
		return true
	}

	return e.Prefixed && target == ErrInvalidConfig
}

// RequiredFieldError is returned when a required tool input field is empty.
// errors.Is matches the sentinel for Field when known.
type RequiredFieldError struct {
	Field string
}

// Error returns a message naming the required field.
func (e *RequiredFieldError) Error() string {
	switch e.Field {
	case "requestValues":
		return ErrRequestValuesRequired.Error()
	default:
		return fmt.Sprintf("%s is required", e.Field)
	}
}

// Is reports whether target matches the sentinel for Field.
func (e *RequiredFieldError) Is(target error) bool {
	switch e.Field {
	case "publicKeyFile":
		return target == ErrPublicKeyFileRequired
	case "requestValues":
		return target == ErrRequestValuesRequired
	default:
		return false
	}
}
