package certinfo

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertinfo_errorSentinels_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "EmptyArgError",
			err:    &EmptyArgError{Name: "caBundlePath"},
			target: ErrEmptyArg,
		},
		{
			name:   "EmptyArgError wrapped",
			err:    fmt.Errorf("load: %w", &EmptyArgError{Name: "keyFilePath"}),
			target: ErrEmptyArg,
		},
		{
			name:   "NoCertsInFileError",
			err:    &NoCertsInFileError{Path: "bundle.pem"},
			target: ErrNoCertsInFile,
		},
		{
			name:   "UnrecognizedKeyTypeError",
			err:    &UnrecognizedKeyTypeError{Type: "FOO"},
			target: ErrUnrecognizedKeyType,
		},
		{
			name:   "ErrNilReader wrapped",
			err:    fmt.Errorf("op: %w", ErrNilReader),
			target: ErrNilReader,
		},
		{
			name:   "ErrPEMDecode",
			err:    ErrPEMDecode,
			target: ErrPEMDecode,
		},
		{
			name:   "ErrCertPoolFromFile",
			err:    ErrCertPoolFromFile,
			target: ErrCertPoolFromFile,
		},
		{
			name:   "ErrNoCertsInConfig",
			err:    ErrNoCertsInConfig,
			target: ErrNoCertsInConfig,
		},
		{
			name:   "ErrUnsupportedKey",
			err:    ErrUnsupportedKey,
			target: ErrUnsupportedKey,
		},
		{
			name:   "ErrUnsupportedPublicKey",
			err:    ErrUnsupportedPublicKey,
			target: ErrUnsupportedPublicKey,
		},
		{
			name:   "InvalidTLSEndpointError",
			err:    &InvalidTLSEndpointError{Endpoint: "bad"},
			target: ErrInvalidTLSEndpoint,
		},
		{
			name:   "InvalidTLSEndpointError wrapped",
			err:    fmt.Errorf("set: %w", &InvalidTLSEndpointError{Endpoint: "x"}),
			target: ErrInvalidTLSEndpoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tt.err, tt.target)
		})
	}
}

func TestCertinfo_errorTypes_AsType(t *testing.T) {
	t.Parallel()

	empty := fmt.Errorf("wrap: %w", &EmptyArgError{Name: "certBundlePath"})
	gotEmpty, ok := errors.AsType[*EmptyArgError](empty)
	require.True(t, ok)
	require.Equal(t, "certBundlePath", gotEmpty.Name)

	noCerts := fmt.Errorf("wrap: %w", &NoCertsInFileError{Path: "a.pem"})
	gotNoCerts, ok := errors.AsType[*NoCertsInFileError](noCerts)
	require.True(t, ok)
	require.Equal(t, "a.pem", gotNoCerts.Path)

	keyType := fmt.Errorf("wrap: %w", &UnrecognizedKeyTypeError{Type: "CERTIFICATE"})
	gotKeyType, ok := errors.AsType[*UnrecognizedKeyTypeError](keyType)
	require.True(t, ok)
	require.Equal(t, "CERTIFICATE", gotKeyType.Type)

	tlsEp := fmt.Errorf("wrap: %w", &InvalidTLSEndpointError{Endpoint: "no-port"})
	gotTLS, ok := errors.AsType[*InvalidTLSEndpointError](tlsEp)
	require.True(t, ok)
	require.Equal(t, "no-port", gotTLS.Endpoint)
}
