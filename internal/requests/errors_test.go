package requests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRequests_errorSentinels_Is checks errors.Is against requests sentinels.
func TestRequests_errorSentinels_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "EmptyArgError",
			err:    &EmptyArgError{Name: "serverName"},
			target: ErrEmptyArg,
		},
		{
			name:   "EmptyArgError wrapped",
			err:    fmt.Errorf("SetServerName error: %w", &EmptyArgError{Name: "serverName"}),
			target: ErrEmptyArg,
		},
		{
			name:   "ServerNameURLError",
			err:    &ServerNameURLError{Value: "https://x"},
			target: ErrServerNameIsURL,
		},
		{
			name:   "WrongTransportError",
			err:    &WrongTransportError{Got: nil},
			target: ErrWrongTransport,
		},
		{
			name:   "InvalidTimeoutError",
			err:    &InvalidTimeoutError{Value: -1},
			target: ErrInvalidTimeout,
		},
		{
			name:   "InvalidURIError",
			err:    &InvalidURIError{URI: "/bad", Host: "h"},
			target: ErrInvalidURI,
		},
		{
			name:   "InvalidTransportURLError",
			err:    &InvalidTransportURLError{URL: "bad"},
			target: ErrInvalidTransportURL,
		},
		{
			name:   "ErrNilClient wrapped",
			err:    fmt.Errorf("op: %w", ErrNilClient),
			target: ErrNilClient,
		},
		{
			name:   "ErrProxyProtoNeedsOverride",
			err:    ErrProxyProtoNeedsOverride,
			target: ErrProxyProtoNeedsOverride,
		},
		{
			name:   "ErrProxyProtoDisabled",
			err:    ErrProxyProtoDisabled,
			target: ErrProxyProtoDisabled,
		},
		{
			name:   "ErrTransportOverrideRequired",
			err:    ErrTransportOverrideRequired,
			target: ErrTransportOverrideRequired,
		},
		{
			name:   "ErrMethodNotFound",
			err:    fmt.Errorf("FOO: %w", ErrMethodNotFound),
			target: ErrMethodNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tt.err, tt.target)
		})
	}
}

// TestRequests_errorTypes_AsType checks errors.AsType for typed requests errors.
func TestRequests_errorTypes_AsType(t *testing.T) {
	t.Parallel()

	empty := fmt.Errorf("wrap: %w", &EmptyArgError{Name: "transportURL"})
	gotEmpty, ok := errors.AsType[*EmptyArgError](empty)
	require.True(t, ok)
	require.Equal(t, "transportURL", gotEmpty.Name)

	urlErr := fmt.Errorf("wrap: %w", &ServerNameURLError{Value: "https://x"})
	gotURL, ok := errors.AsType[*ServerNameURLError](urlErr)
	require.True(t, ok)
	require.Equal(t, "https://x", gotURL.Value)

	timeout := fmt.Errorf("wrap: %w", &InvalidTimeoutError{Value: -1})
	gotTimeout, ok := errors.AsType[*InvalidTimeoutError](timeout)
	require.True(t, ok)
	require.Equal(t, -1, gotTimeout.Value)

	uri := fmt.Errorf("wrap: %w", &InvalidURIError{URI: "/x", Host: "h"})
	gotURI, ok := errors.AsType[*InvalidURIError](uri)
	require.True(t, ok)
	require.Equal(t, "/x", gotURI.URI)
	require.Equal(t, "h", gotURI.Host)
}
