/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package errdisp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
)

func TestCause(t *testing.T) {
	t.Parallel()

	require.NoError(t, Cause(nil))

	leaf := errors.New("leaf")
	require.Equal(t, leaf, Cause(leaf))

	wrapped := fmt.Errorf("mid: %w", fmt.Errorf("inner: %w", leaf))
	require.Equal(t, leaf, Cause(wrapped))
}

// TestFormatCause checks FormatCause prefers domain leaves over wrap text.
func TestFormatCause(t *testing.T) {
	t.Parallel()

	require.Empty(t, FormatCause(nil))

	t.Run("os cause under read wrap", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("failed to read CA bundle file: %w", errors.New("open x: no such file or directory"))
		require.Equal(t, "open x: no such file or directory", FormatCause(err))
	})

	t.Run("PEM sentinel", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("error reading private key file: %w", certinfo.ErrPEMDecode)
		require.Equal(t, certinfo.ErrPEMDecode.Error(), FormatCause(err))
	})

	t.Run("typed no certs", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("wrap: %w", &certinfo.NoCertsInFileError{Path: "a.pem"})
		require.Equal(t, "no valid certificates found in file a.pem", FormatCause(err))
	})

	t.Run("typed empty arg", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("wrap: %w", &certinfo.EmptyArgError{Name: "caBundlePath"})
		require.Equal(t, "empty string provided as caBundlePath", FormatCause(err))
	})

	t.Run("jwtinfo empty arg", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("wrap: %w", &jwtinfo.EmptyArgError{Name: "request URL"})
		require.Equal(t, "empty string provided as request URL", FormatCause(err))
	})

	t.Run("jwtinfo token status", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("request: %w", &jwtinfo.TokenStatusError{Code: 401})
		require.Equal(t, "token request returned the following status code: 401", FormatCause(err))
	})

	t.Run("jwtinfo claim missing", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("claims: %w", &jwtinfo.ClaimError{Claim: "exp", Kind: jwtinfo.ClaimMissing})
		require.Equal(t, "exp claim missing", FormatCause(err))
	})
}

// TestFormat checks Format surfaces domain leaves or top label plus cause.
func TestFormat(t *testing.T) {
	t.Parallel()

	require.Empty(t, Format(nil))

	t.Run("leaf only for sentinel", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("unable to create CA Certs Pool from YAML: %w", certinfo.ErrNoCertsInConfig)
		require.Equal(t, certinfo.ErrNoCertsInConfig.Error(), Format(err))
	})

	t.Run("top context and cause skips middle", func(t *testing.T) {
		t.Parallel()

		leaf := errors.New("open x: no such file or directory")
		err := fmt.Errorf(
			"unable to get endpoint certificates: %w",
			fmt.Errorf("TLS handshake failed: %w", leaf),
		)
		require.Equal(t, "unable to get endpoint certificates: open x: no such file or directory", Format(err))
	})

	t.Run("bare leaf", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, "boom", Format(errors.New("boom")))
	})

	t.Run("jwtinfo sentinel leaf only", func(t *testing.T) {
		t.Parallel()

		err := fmt.Errorf("failed to request refreshed token: %w", jwtinfo.ErrEmptyRequestValues)
		require.Equal(t, jwtinfo.ErrEmptyRequestValues.Error(), Format(err))
	})
}
