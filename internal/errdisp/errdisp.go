/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

// Package errdisp formats errors for CLI and MCP user boundaries.
// It holds no sentinels; domain identity stays in packages such as certinfo.
package errdisp

import (
	"errors"
	"strings"

	"github.com/xenos76/https-wrench/internal/certinfo"
)

// Cause returns the deepest single-cause unwrap of err.
// Multi-cause Join chains are left as-is (no invented multi-cause UX).
func Cause(err error) error {
	for err != nil {
		u := errors.Unwrap(err)
		if u == nil {
			return err
		}

		err = u
	}

	return err
}

// FormatCause returns a short message for callers that already print an
// operation prefix. Prefer certinfo domain leaves via Is/As; otherwise the
// deepest cause.
func FormatCause(err error) string {
	if err == nil {
		return ""
	}

	if msg, ok := domainLeaf(err); ok {
		return msg
	}

	return Cause(err).Error()
}

// Format returns a user-facing message when the caller has no operation prefix.
// Prefer certinfo domain leaves via Is/As; otherwise top wrap label + deepest
// cause, skipping intermediate layers.
func Format(err error) string {
	if err == nil {
		return ""
	}

	if msg, ok := domainLeaf(err); ok {
		return msg
	}

	if errors.Unwrap(err) == nil {
		return err.Error()
	}

	cause := Cause(err)
	label := topLabel(err)

	if label == "" || label == cause.Error() {
		return cause.Error()
	}

	return label + ": " + cause.Error()
}

// domainLeaf returns a certinfo leaf message when err matches a known domain failure.
func domainLeaf(err error) (string, bool) {
	if empty, ok := errors.AsType[*certinfo.EmptyArgError](err); ok {
		return empty.Error(), true
	}

	if noCerts, ok := errors.AsType[*certinfo.NoCertsInFileError](err); ok {
		return noCerts.Error(), true
	}

	if keyType, ok := errors.AsType[*certinfo.UnrecognizedKeyTypeError](err); ok {
		return keyType.Error(), true
	}

	for _, s := range []error{
		certinfo.ErrNilReader,
		certinfo.ErrPEMDecode,
		certinfo.ErrCertPoolFromFile,
		certinfo.ErrNoCertsInConfig,
		certinfo.ErrUnsupportedKey,
		certinfo.ErrUnsupportedPublicKey,
		certinfo.ErrEmptyArg,
		certinfo.ErrNoCertsInFile,
		certinfo.ErrUnrecognizedKeyType,
	} {
		if errors.Is(err, s) {
			return s.Error(), true
		}
	}

	return "", false
}

// topLabel returns the outermost wrap text without the unwrapped suffix.
func topLabel(err error) string {
	u := errors.Unwrap(err)
	if u == nil {
		return err.Error()
	}

	full := err.Error()

	suffix := ": " + u.Error()
	if after, ok := strings.CutSuffix(full, suffix); ok {
		return after
	}

	return full
}
