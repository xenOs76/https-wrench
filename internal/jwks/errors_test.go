package jwks

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJwks_errorSentinels_Is checks errors.Is against jwks sentinels.
func TestJwks_errorSentinels_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "ErrPEMDecode",
			err:    ErrPEMDecode,
			target: ErrPEMDecode,
		},
		{
			name:   "ErrPEMDecode wrapped",
			err:    fmt.Errorf("generate: %w", ErrPEMDecode),
			target: ErrPEMDecode,
		},
		{
			name:   "ErrUnsupportedPublicKey wrapped",
			err:    fmt.Errorf("%w: %w", ErrUnsupportedPublicKey, errors.New("bad key")),
			target: ErrUnsupportedPublicKey,
		},
		{
			name:   "ErrNotPublicKey",
			err:    ErrNotPublicKey,
			target: ErrNotPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tt.err, tt.target)
		})
	}
}
