//nolint:revive // max-public-structs: typed domain errors for errors.Is/As
package jwtinfo

import (
	"errors"
	"fmt"
)

// Package-level sentinels for stable jwtinfo failure conditions.
// Match them with errors.Is after wrapping; Error() strings stay human-facing.
var (
	ErrNilBodyReader         = errors.New("nil body reader function")
	ErrEmptyRequestValues    = errors.New("empty map provided as request values")
	ErrEmptyArg              = errors.New("empty string provided as argument")
	ErrInvalidJWTFormat      = errors.New("invalid three dotted JWT format")
	ErrInvalidHeaderJSON     = errors.New("invalid JSON found in header")
	ErrInvalidClaimsJSON     = errors.New("invalid JSON found in claims")
	ErrEmptyClaims           = errors.New("access token claims are empty")
	ErrClaimMissing          = errors.New("required claim missing")
	ErrClaimNotNumeric       = errors.New("claim is not a numeric timestamp")
	ErrInvalidKV             = errors.New("invalid key-value pair")
	ErrEmptyParamName        = errors.New("empty request parameter name")
	ErrInvalidRenewThreshold = errors.New("renewThreshold must be between 0 and 100")
	ErrTokenLifetimeInvalid  = errors.New("token lifetime is zero or negative")
	ErrTokenRequestStatus    = errors.New("token request returned non-OK status")
)

// EmptyArgError is returned when a required string argument is empty.
// errors.Is(err, ErrEmptyArg) is true.
type EmptyArgError struct {
	Name string
}

// Error returns a message naming the empty argument.
func (e *EmptyArgError) Error() string {
	return fmt.Sprintf("empty string provided as %s", e.Name)
}

// Is reports whether target is ErrEmptyArg.
func (*EmptyArgError) Is(target error) bool {
	return target == ErrEmptyArg
}

// InvalidJWTFormatError is returned when a token is not three dotted JWT parts.
// errors.Is(err, ErrInvalidJWTFormat) is true.
type InvalidJWTFormatError struct {
	Name string
}

// Error returns a message naming the malformed token.
func (e *InvalidJWTFormatError) Error() string {
	return fmt.Sprintf("invalid three dotted JWT format in %s", e.Name)
}

// Is reports whether target is ErrInvalidJWTFormat.
func (*InvalidJWTFormatError) Is(target error) bool {
	return target == ErrInvalidJWTFormat
}

// InvalidJSONPartError is returned when a JWT header or claims part is not JSON.
// errors.Is matches ErrInvalidHeaderJSON or ErrInvalidClaimsJSON from Part.
type InvalidJSONPartError struct {
	Name string
	Part string // "header" or "claims"
}

// Error returns a message naming the invalid JSON part.
func (e *InvalidJSONPartError) Error() string {
	return fmt.Sprintf("invalid JSON found in %s from %s", e.Part, e.Name)
}

// Is reports whether target matches the header or claims sentinel for Part.
func (e *InvalidJSONPartError) Is(target error) bool {
	switch e.Part {
	case "header":
		return target == ErrInvalidHeaderJSON
	case "claims":
		return target == ErrInvalidClaimsJSON
	default:
		return false
	}
}

// ClaimKind distinguishes missing vs non-numeric claim failures.
type ClaimKind int

const (
	// ClaimMissing means the claim key is absent.
	ClaimMissing ClaimKind = iota
	// ClaimNotNumeric means the claim exists but is not a numeric timestamp.
	ClaimNotNumeric
)

// ClaimError is returned for iat/exp claim validation failures.
// errors.Is matches ErrClaimMissing or ErrClaimNotNumeric from Kind.
type ClaimError struct {
	Claim string
	Kind  ClaimKind
}

// Error returns a human-facing claim failure message.
func (e *ClaimError) Error() string {
	switch e.Kind {
	case ClaimNotNumeric:
		return fmt.Sprintf("%s claim is not a numeric timestamp", e.Claim)
	default:
		return fmt.Sprintf("%s claim missing", e.Claim)
	}
}

// Is reports whether target matches the sentinel for Kind.
func (e *ClaimError) Is(target error) bool {
	switch e.Kind {
	case ClaimNotNumeric:
		return target == ErrClaimNotNumeric
	default:
		return target == ErrClaimMissing
	}
}

// TokenStatusError is returned when the token HTTP request is not StatusOK.
// errors.Is(err, ErrTokenRequestStatus) is true.
type TokenStatusError struct {
	Code int
}

// Error returns a message including the HTTP status code.
func (e *TokenStatusError) Error() string {
	return fmt.Sprintf("token request returned the following status code: %d", e.Code)
}

// Is reports whether target is ErrTokenRequestStatus.
func (*TokenStatusError) Is(target error) bool {
	return target == ErrTokenRequestStatus
}

// InvalidKVError is returned when a key-value string is not key=value.
// errors.Is(err, ErrInvalidKV) is true.
type InvalidKVError struct {
	Value string
}

// Error returns a message including the invalid value.
func (e *InvalidKVError) Error() string {
	return fmt.Sprintf("invalid key-value pair: %s (expected key=value)", e.Value)
}

// Is reports whether target is ErrInvalidKV.
func (*InvalidKVError) Is(target error) bool {
	return target == ErrInvalidKV
}

// EmptyParamNameError is returned when the key side of key=value is empty.
// errors.Is(err, ErrEmptyParamName) is true.
type EmptyParamNameError struct {
	KV string
}

// Error returns a message including the original key-value string.
func (e *EmptyParamNameError) Error() string {
	return fmt.Sprintf("empty request parameter name in: %s", e.KV)
}

// Is reports whether target is ErrEmptyParamName.
func (*EmptyParamNameError) Is(target error) bool {
	return target == ErrEmptyParamName
}

// InvalidRenewThresholdError is returned when renewThreshold is out of range.
// errors.Is(err, ErrInvalidRenewThreshold) is true.
type InvalidRenewThresholdError struct {
	Value float64
}

// Error returns a message including the invalid threshold.
func (e *InvalidRenewThresholdError) Error() string {
	return fmt.Sprintf("renewThreshold must be between 0 and 100, got %.2f", e.Value)
}

// Is reports whether target is ErrInvalidRenewThreshold.
func (*InvalidRenewThresholdError) Is(target error) bool {
	return target == ErrInvalidRenewThreshold
}
