package certinfo

import (
	"errors"
	"fmt"
)

// Package-level sentinels for stable certinfo failure conditions.
// Match them with errors.Is after wrapping; Error() strings stay human-facing.
var (
	ErrNilReader            = errors.New("nil Reader provided")
	ErrPEMDecode            = errors.New("failed to decode PEM")
	ErrCertPoolFromFile     = errors.New("unable to create CertPool from file")
	ErrNoCertsInConfig      = errors.New("no valid certs in caBundle config string")
	ErrUnsupportedKey       = errors.New("unsupported key format or invalid password")
	ErrUnsupportedPublicKey = errors.New("unsupported public key type in certificate")
	ErrEmptyArg             = errors.New("empty string provided as argument")
	ErrNoCertsInFile        = errors.New("no valid certificates found in file")
	ErrUnrecognizedKeyType  = errors.New("unrecognized private key type")
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

// NoCertsInFileError is returned when a PEM file yields no certificates.
// errors.Is(err, ErrNoCertsInFile) is true.
type NoCertsInFileError struct {
	Path string
}

// Error returns a message including the PEM file path.
func (e *NoCertsInFileError) Error() string {
	return fmt.Sprintf("no valid certificates found in file %s", e.Path)
}

// Is reports whether target is ErrNoCertsInFile.
func (*NoCertsInFileError) Is(target error) bool {
	return target == ErrNoCertsInFile
}

// UnrecognizedKeyTypeError is returned for an unknown PEM private-key type.
// errors.Is(err, ErrUnrecognizedKeyType) is true.
type UnrecognizedKeyTypeError struct {
	Type string
}

// Error returns a message including the unrecognized PEM type.
func (e *UnrecognizedKeyTypeError) Error() string {
	return fmt.Sprintf("unrecognized private key type: %s", e.Type)
}

// Is reports whether target is ErrUnrecognizedKeyType.
func (*UnrecognizedKeyTypeError) Is(target error) bool {
	return target == ErrUnrecognizedKeyType
}
