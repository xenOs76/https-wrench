/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

// Package errdisp formats errors for CLI and MCP user boundaries.
// It holds no sentinels; domain identity stays in packages such as certinfo,
// jwtinfo, jwks, and requests. MCP tool-boundary errors stay in package mcp
// (errdisp cannot import mcp without a cycle); bare MCP leaves still format
// via Error() when Format finds no registered domain leaf.
package errdisp

import (
	"errors"
	"strings"

	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/jwks"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
	"github.com/xenos76/https-wrench/internal/requests"
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
// operation prefix. Prefer domain leaves via Is/As; otherwise the deepest
// cause.
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
// Prefer domain leaves via Is/As; otherwise top wrap label + deepest cause,
// skipping intermediate layers.
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

// domainLeaf returns a domain leaf message when err matches a known failure.
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

	if tlsEp, ok := errors.AsType[*certinfo.InvalidTLSEndpointError](err); ok {
		return tlsEp.Error(), true
	}

	if empty, ok := errors.AsType[*jwtinfo.EmptyArgError](err); ok {
		return empty.Error(), true
	}

	if jwtFmt, ok := errors.AsType[*jwtinfo.InvalidJWTFormatError](err); ok {
		return jwtFmt.Error(), true
	}

	if jsonPart, ok := errors.AsType[*jwtinfo.InvalidJSONPartError](err); ok {
		return jsonPart.Error(), true
	}

	if claim, ok := errors.AsType[*jwtinfo.ClaimError](err); ok {
		return claim.Error(), true
	}

	if status, ok := errors.AsType[*jwtinfo.TokenStatusError](err); ok {
		return status.Error(), true
	}

	if kv, ok := errors.AsType[*jwtinfo.InvalidKVError](err); ok {
		return kv.Error(), true
	}

	if param, ok := errors.AsType[*jwtinfo.EmptyParamNameError](err); ok {
		return param.Error(), true
	}

	if thr, ok := errors.AsType[*jwtinfo.InvalidRenewThresholdError](err); ok {
		return thr.Error(), true
	}

	if b64, ok := errors.AsType[*jwtinfo.InvalidBase64PartError](err); ok {
		return b64.Error(), true
	}

	if parse, ok := errors.AsType[*jwtinfo.JWTParseError](err); ok {
		return parse.Error(), true
	}

	if empty, ok := errors.AsType[*requests.EmptyArgError](err); ok {
		return empty.Error(), true
	}

	if snURL, ok := errors.AsType[*requests.ServerNameURLError](err); ok {
		return snURL.Error(), true
	}

	if wt, ok := errors.AsType[*requests.WrongTransportError](err); ok {
		return wt.Error(), true
	}

	if to, ok := errors.AsType[*requests.InvalidTimeoutError](err); ok {
		return to.Error(), true
	}

	if uri, ok := errors.AsType[*requests.InvalidURIError](err); ok {
		return uri.Error(), true
	}

	if turl, ok := errors.AsType[*requests.InvalidTransportURLError](err); ok {
		return turl.Error(), true
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
		certinfo.ErrInvalidTLSEndpoint,
		jwtinfo.ErrNilBodyReader,
		jwtinfo.ErrEmptyRequestValues,
		jwtinfo.ErrEmptyArg,
		jwtinfo.ErrInvalidJWTFormat,
		jwtinfo.ErrInvalidHeaderJSON,
		jwtinfo.ErrInvalidClaimsJSON,
		jwtinfo.ErrEmptyClaims,
		jwtinfo.ErrClaimMissing,
		jwtinfo.ErrClaimNotNumeric,
		jwtinfo.ErrInvalidKV,
		jwtinfo.ErrEmptyParamName,
		jwtinfo.ErrInvalidRenewThreshold,
		jwtinfo.ErrTokenLifetimeInvalid,
		jwtinfo.ErrTokenRequestStatus,
		jwtinfo.ErrInvalidBase64Header,
		jwtinfo.ErrInvalidBase64Claims,
		jwtinfo.ErrJWTParse,
		jwtinfo.ErrInvalidRequestJSON,
		jwks.ErrPEMDecode,
		jwks.ErrUnsupportedPublicKey,
		jwks.ErrNotPublicKey,
		requests.ErrMethodNotFound,
		requests.ErrNilClient,
		requests.ErrEmptyArg,
		requests.ErrServerNameIsURL,
		requests.ErrWrongTransport,
		requests.ErrInvalidTimeout,
		requests.ErrProxyProtoNeedsOverride,
		requests.ErrProxyProtoDisabled,
		requests.ErrTransportOverrideRequired,
		requests.ErrInvalidURI,
		requests.ErrInvalidTransportURL,
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
