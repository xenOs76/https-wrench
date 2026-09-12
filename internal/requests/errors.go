//nolint:revive // max-public-structs: typed domain errors for errors.Is/As
package requests

import (
	"errors"
	"fmt"
)

// Package-level sentinels for stable requests failure conditions.
// Match them with errors.Is after wrapping; Error() strings stay human-facing.
var (
	// ErrMethodNotFound is returned when an unsupported HTTP method is specified.
	ErrMethodNotFound = errors.New("HTTP method not found")

	ErrNilClient = errors.New(
		"*RequestHTTPClient.client is nil. Use NewRequestHTTPClient to initialize",
	)
	ErrEmptyArg                = errors.New("empty string provided as argument")
	ErrServerNameIsURL         = errors.New("serverName should be a hostname, not a URL")
	ErrWrongTransport          = errors.New("expected *http.Transport")
	ErrInvalidTimeout          = errors.New("timeout value must be positive")
	ErrProxyProtoNeedsOverride = errors.New(
		"if EnableProxyProtocolV2 is true, a TransportOverrideURL must be set",
	)
	ErrProxyProtoDisabled        = errors.New("proxy protocol v2 is not enabled for this request")
	ErrTransportOverrideRequired = errors.New(
		"SetProxyProtocolHeader failed: transportOverrideURL not set",
	)
	ErrInvalidURI          = errors.New("invalid uri")
	ErrInvalidTransportURL = errors.New("failed to parse transport override url")
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

// ServerNameURLError is returned when serverName looks like a URL.
// errors.Is(err, ErrServerNameIsURL) is true.
type ServerNameURLError struct {
	Value string
}

// Error returns a message including the invalid serverName.
func (e *ServerNameURLError) Error() string {
	return fmt.Sprintf("serverName should be a hostname, not a URL: %s", e.Value)
}

// Is reports whether target is ErrServerNameIsURL.
func (*ServerNameURLError) Is(target error) bool {
	return target == ErrServerNameIsURL
}

// WrongTransportError is returned when the client transport is not *http.Transport.
// errors.Is(err, ErrWrongTransport) is true.
type WrongTransportError struct {
	Got any
}

// Error returns a message including the unexpected transport type.
func (e *WrongTransportError) Error() string {
	return fmt.Sprintf("expected *http.Transport, got %T", e.Got)
}

// Is reports whether target is ErrWrongTransport.
func (*WrongTransportError) Is(target error) bool {
	return target == ErrWrongTransport
}

// InvalidTimeoutError is returned when client timeout is negative.
// errors.Is(err, ErrInvalidTimeout) is true.
type InvalidTimeoutError struct {
	Value int
}

// Error returns a message including the invalid timeout.
func (e *InvalidTimeoutError) Error() string {
	return fmt.Sprintf("timeout value must be positive: %v provided", e.Value)
}

// Is reports whether target is ErrInvalidTimeout.
func (*InvalidTimeoutError) Is(target error) bool {
	return target == ErrInvalidTimeout
}

// InvalidURIError is returned when a host URI fails Parse.
// errors.Is(err, ErrInvalidURI) is true.
type InvalidURIError struct {
	URI  string
	Host string
}

// Error returns a message including the invalid URI and host.
func (e *InvalidURIError) Error() string {
	return fmt.Sprintf("invalid uri %s for host %s", e.URI, e.Host)
}

// Is reports whether target is ErrInvalidURI.
func (*InvalidURIError) Is(target error) bool {
	return target == ErrInvalidURI
}

// InvalidTransportURLError is returned when a transport override URL cannot be parsed.
// errors.Is(err, ErrInvalidTransportURL) is true.
type InvalidTransportURLError struct {
	URL string
}

// Error returns a message including the invalid transport URL.
func (e *InvalidTransportURLError) Error() string {
	return fmt.Sprintf("failed to parse transport override url: %s", e.URL)
}

// Is reports whether target is ErrInvalidTransportURL.
func (*InvalidTransportURLError) Is(target error) bool {
	return target == ErrInvalidTransportURL
}
