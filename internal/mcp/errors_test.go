package mcp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMCP_errorSentinels_Is checks errors.Is against mcp sentinels.
//
//nolint:revive // function-length: table-driven sentinel coverage
func TestMCP_errorSentinels_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "ErrExactlyOneConfigSource",
			err:    ErrExactlyOneConfigSource,
			target: ErrExactlyOneConfigSource,
		},
		{
			name:   "ErrConfigSourceRequired wrapped",
			err:    fmt.Errorf("load: %w", ErrConfigSourceRequired),
			target: ErrConfigSourceRequired,
		},
		{
			name:   "ErrExactlyOneTokenSource",
			err:    ErrExactlyOneTokenSource,
			target: ErrExactlyOneTokenSource,
		},
		{
			name:   "ErrTokenSourceRequired",
			err:    ErrTokenSourceRequired,
			target: ErrTokenSourceRequired,
		},
		{
			name:   "RequiredFieldError publicKeyFile",
			err:    &RequiredFieldError{Field: "publicKeyFile"},
			target: ErrPublicKeyFileRequired,
		},
		{
			name:   "RequiredFieldError requestValues",
			err:    &RequiredFieldError{Field: "requestValues"},
			target: ErrRequestValuesRequired,
		},
		{
			name:   "ErrCertinfoInputRequired",
			err:    ErrCertinfoInputRequired,
			target: ErrCertinfoInputRequired,
		},
		{
			name:   "ErrTLSInfoNeedsEndpoint",
			err:    ErrTLSInfoNeedsEndpoint,
			target: ErrTLSInfoNeedsEndpoint,
		},
		{
			name:   "ErrEncryptedKeyNeedsEnv",
			err:    ErrEncryptedKeyNeedsEnv,
			target: ErrEncryptedKeyNeedsEnv,
		},
		{
			name:   "ErrNoJWTTokenData",
			err:    ErrNoJWTTokenData,
			target: ErrNoJWTTokenData,
		},
		{
			name:   "ValidationError ErrValidation",
			err:    &ValidationError{Messages: []string{"a", "b"}},
			target: ErrValidation,
		},
		{
			name:   "ValidationError ErrInvalidConfig when Prefixed",
			err:    &ValidationError{Messages: []string{"x"}, Prefixed: true},
			target: ErrInvalidConfig,
		},
		{
			name:   "ValidationError Prefixed also ErrValidation",
			err:    &ValidationError{Messages: []string{"x"}, Prefixed: true},
			target: ErrValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tt.err, tt.target)
		})
	}
}

func TestMCP_errorTypes_AsType(t *testing.T) {
	t.Parallel()

	ve := fmt.Errorf("wrap: %w", &ValidationError{Messages: []string{"a"}, Prefixed: true})
	gotVE, ok := errors.AsType[*ValidationError](ve)
	require.True(t, ok)
	require.True(t, gotVE.Prefixed)
	require.Equal(t, []string{"a"}, gotVE.Messages)
	require.Equal(t, "invalid config: a", gotVE.Error())

	rf := fmt.Errorf("wrap: %w", &RequiredFieldError{Field: "publicKeyFile"})
	gotRF, ok := errors.AsType[*RequiredFieldError](rf)
	require.True(t, ok)
	require.Equal(t, "publicKeyFile", gotRF.Field)
}
