package jwtinfo

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJwtinfo_errorSentinels_Is checks errors.Is against jwtinfo sentinels.
//
//nolint:revive // function-length: table-driven sentinel coverage
func TestJwtinfo_errorSentinels_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "EmptyArgError",
			err:    &EmptyArgError{Name: "request URL"},
			target: ErrEmptyArg,
		},
		{
			name:   "EmptyArgError wrapped",
			err:    fmt.Errorf("load: %w", &EmptyArgError{Name: "JWKS url"}),
			target: ErrEmptyArg,
		},
		{
			name:   "InvalidJWTFormatError",
			err:    &InvalidJWTFormatError{Name: "AccessToken"},
			target: ErrInvalidJWTFormat,
		},
		{
			name:   "InvalidJSONPartError header",
			err:    &InvalidJSONPartError{Name: "AccessToken", Part: "header"},
			target: ErrInvalidHeaderJSON,
		},
		{
			name:   "InvalidJSONPartError claims",
			err:    &InvalidJSONPartError{Name: "RefreshToken", Part: "claims"},
			target: ErrInvalidClaimsJSON,
		},
		{
			name:   "ClaimError missing",
			err:    &ClaimError{Claim: "iat", Kind: ClaimMissing},
			target: ErrClaimMissing,
		},
		{
			name:   "ClaimError not numeric",
			err:    &ClaimError{Claim: "exp", Kind: ClaimNotNumeric},
			target: ErrClaimNotNumeric,
		},
		{
			name:   "TokenStatusError",
			err:    &TokenStatusError{Code: 503},
			target: ErrTokenRequestStatus,
		},
		{
			name:   "InvalidKVError",
			err:    &InvalidKVError{Value: "nope"},
			target: ErrInvalidKV,
		},
		{
			name:   "EmptyParamNameError",
			err:    &EmptyParamNameError{KV: "=value"},
			target: ErrEmptyParamName,
		},
		{
			name:   "InvalidRenewThresholdError",
			err:    &InvalidRenewThresholdError{Value: 150},
			target: ErrInvalidRenewThreshold,
		},
		{
			name:   "ErrNilBodyReader wrapped",
			err:    fmt.Errorf("op: %w", ErrNilBodyReader),
			target: ErrNilBodyReader,
		},
		{
			name:   "ErrEmptyRequestValues",
			err:    ErrEmptyRequestValues,
			target: ErrEmptyRequestValues,
		},
		{
			name:   "ErrEmptyClaims",
			err:    ErrEmptyClaims,
			target: ErrEmptyClaims,
		},
		{
			name:   "ErrTokenLifetimeInvalid",
			err:    ErrTokenLifetimeInvalid,
			target: ErrTokenLifetimeInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tt.err, tt.target)
		})
	}
}

// TestJwtinfo_errorTypes_AsType checks errors.AsType for typed jwtinfo errors.
func TestJwtinfo_errorTypes_AsType(t *testing.T) {
	t.Parallel()

	empty := fmt.Errorf("wrap: %w", &EmptyArgError{Name: "request URL"})
	gotEmpty, ok := errors.AsType[*EmptyArgError](empty)
	require.True(t, ok)
	require.Equal(t, "request URL", gotEmpty.Name)

	jwtFmt := fmt.Errorf("wrap: %w", &InvalidJWTFormatError{Name: "AccessToken"})
	gotFmt, ok := errors.AsType[*InvalidJWTFormatError](jwtFmt)
	require.True(t, ok)
	require.Equal(t, "AccessToken", gotFmt.Name)

	jsonPart := fmt.Errorf("wrap: %w", &InvalidJSONPartError{Name: "AccessToken", Part: "header"})
	gotPart, ok := errors.AsType[*InvalidJSONPartError](jsonPart)
	require.True(t, ok)
	require.Equal(t, "header", gotPart.Part)

	claim := fmt.Errorf("wrap: %w", &ClaimError{Claim: "exp", Kind: ClaimMissing})
	gotClaim, ok := errors.AsType[*ClaimError](claim)
	require.True(t, ok)
	require.Equal(t, "exp", gotClaim.Claim)
	require.Equal(t, ClaimMissing, gotClaim.Kind)

	status := fmt.Errorf("wrap: %w", &TokenStatusError{Code: 401})
	gotStatus, ok := errors.AsType[*TokenStatusError](status)
	require.True(t, ok)
	require.Equal(t, 401, gotStatus.Code)

	kv := fmt.Errorf("wrap: %w", &InvalidKVError{Value: "x"})
	gotKV, ok := errors.AsType[*InvalidKVError](kv)
	require.True(t, ok)
	require.Equal(t, "x", gotKV.Value)

	param := fmt.Errorf("wrap: %w", &EmptyParamNameError{KV: "=v"})
	gotParam, ok := errors.AsType[*EmptyParamNameError](param)
	require.True(t, ok)
	require.Equal(t, "=v", gotParam.KV)

	thr := fmt.Errorf("wrap: %w", &InvalidRenewThresholdError{Value: -1})
	gotThr, ok := errors.AsType[*InvalidRenewThresholdError](thr)
	require.True(t, ok)
	require.InDelta(t, -1.0, gotThr.Value, 0.001)
}
