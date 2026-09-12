package jwks

import (
	"errors"
)

// Package-level sentinels for stable jwks failure conditions.
// Match them with errors.Is after wrapping; Error() strings stay human-facing.
var (
	ErrPEMDecode            = errors.New("failed to decode PEM block from public key file")
	ErrUnsupportedPublicKey = errors.New("unsupported or invalid public key format")
	ErrNotPublicKey         = errors.New(
		"the provided file does not contain a supported public key " +
			"(it might be a private key or an unsupported format)",
	)
)
