package certinfo

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/term"
)

const (
	// TLSTimeout is the maximum time to wait for a TLS handshake.
	TLSTimeout = 3 * time.Second
	// CertExpWarnDays is the number of days before expiration to start showing warnings.
	CertExpWarnDays    = 40
	privateKeyPwEnvVar = "CERTINFO_PKEY_PW"
	emptyString        = ""
)

// Config holds the configuration and results for certificate and key information retrieval.
type Config struct {
	// CACertsPool is the pool of root CA certificates used for verification.
	CACertsPool *x509.CertPool
	// CACertsFilePath is the path to the CA certificate bundle file.
	CACertsFilePath string
	// CertsBundle is a slice of certificates loaded from a local bundle.
	CertsBundle []*x509.Certificate
	// CertsBundleFilePath is the path to the certificate bundle file.
	CertsBundleFilePath string
	// CertsBundleFromKey indicates if the certificate was derived from a private key.
	CertsBundleFromKey bool
	// PrivKey is the loaded private key.
	PrivKey crypto.PrivateKey
	// PrivKeyFilePath is the path to the private key file.
	PrivKeyFilePath string
	// TLSEndpoint is the host:port string of the remote TLS endpoint.
	TLSEndpoint string
	// TLSEndpointHost is the hostname part of the TLS endpoint.
	TLSEndpointHost string
	// TLSEndpointPort is the port part of the TLS endpoint.
	TLSEndpointPort string
	// TLSEndpointCerts is the slice of certificates retrieved from the remote endpoint.
	TLSEndpointCerts []*x509.Certificate
	// TLSEndpointCertsFromKey indicates if the endpoint certificates were matched with a private key.
	TLSEndpointCertsFromKey bool
	// TLSServerName is the ServerName used for SNI.
	TLSServerName string
	// TLSInsecure indicates if certificate verification should be skipped.
	TLSInsecure bool
	// TLSInfoRequested indicates if negotiated TLS info and supported protocol/cipher scan was requested.
	TLSInfoRequested bool
	// NegotiatedProtocol is the TLS protocol version negotiated in the primary connection.
	NegotiatedProtocol string
	// NegotiatedCipher is the TLS cipher suite negotiated in the primary connection.
	NegotiatedCipher string
	// ProbedProtocols maps a TLS protocol name to whether the remote endpoint supports it.
	ProbedProtocols map[string]bool
	// ProbedCiphers is a slice of ciphers that were probed against the endpoint.
	ProbedCiphers []ProbedCipher
}

// Reader defines an interface for reading files and passwords.
type (
	Reader interface {
		ReadFile(name string) ([]byte, error)
		ReadPassword(fd int) ([]byte, error)
	}

	// NoPasswordPromptReader is implemented by readers that must not use an
	// interactive terminal prompt (for example MCP or automated tests).
	NoPasswordPromptReader interface {
		NoPasswordPrompt() bool
	}

	// InputReader implements the Reader interface using standard OS calls.
	InputReader struct{}
)

var (
	// TLSServerName is the default ServerName to use for SNI.
	TLSServerName string
	// TLSInsecure indicates if certificate verification should be skipped globally.
	TLSInsecure bool
	inputReader InputReader
)

// ReadFile reads the content of a file from the filesystem.
func (InputReader) ReadFile(name string) ([]byte, error) {
	file, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// ReadPassword reads a password from the terminal without echoing it.
func (InputReader) ReadPassword(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// New creates a new Config with the system's default certificate pool.
func New() (*Config, error) {
	defaultCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	c := Config{
		CACertsPool: defaultCertPool,
	}

	return &c, nil
}

// SetCaPoolFromFile loads a CA certificate pool from the specified PEM bundle file.
// Note that x509.SystemCertPool is not used in this case. All certificates
// from the system certificate pool are excluded.
func (c *Config) SetCaPoolFromFile(filePath string, fileReader Reader) error {
	if filePath != emptyString {
		caCertsPool, err := GetRootCertsFromFile(
			filePath,
			fileReader,
		)
		if err != nil {
			return err
		}

		c.CACertsPool = caCertsPool
		c.CACertsFilePath = filePath
	}

	return nil
}

// SetCertsFromFile loads a certificate bundle from the specified PEM file.
func (c *Config) SetCertsFromFile(filePath string, fileReader Reader) error {
	if filePath != emptyString {
		certs, err := GetCertsFromBundle(
			filePath,
			fileReader,
		)
		if err != nil {
			return err
		}

		c.CertsBundle = certs
		c.CertsBundleFilePath = filePath
	}

	return nil
}

// SetPrivateKeyFromFile loads a private key from the specified PEM file.
// If the key is encrypted, it will attempt to retrieve the passphrase from the environment
// variable passed as argument or from the interactive prompt.
func (c *Config) SetPrivateKeyFromFile(
	filePath string,
	keyPwEnvVar string,
	fileReader Reader,
) error {
	if filePath != emptyString {
		keyFromFile, err := GetKeyFromFile(
			filePath,
			keyPwEnvVar,
			fileReader,
		)
		if err != nil {
			return err
		}

		c.PrivKey = keyFromFile
		c.PrivKeyFilePath = filePath
	}

	return nil
}

// SetTLSEndpoint parses a host:port string and fetches the remote certificates from that endpoint.
func (c *Config) SetTLSEndpoint(hostport string) error {
	if hostport != emptyString {
		eHost, ePort, err := net.SplitHostPort(hostport)
		if err != nil {
			return fmt.Errorf("invalid TLS endpoint %q: %w", hostport, err)
		}

		c.TLSEndpoint = hostport
		c.TLSEndpointHost = eHost
		c.TLSEndpointPort = ePort

		err = c.GetRemoteCerts()
		if err != nil {
			return fmt.Errorf("unable to get endpoint certificates: %w", err)
		}
	}

	return nil
}

// SetTLSInsecure sets whether TLS certificate verification should be skipped for the remote endpoint.
func (c *Config) SetTLSInsecure(skipVerify bool) *Config {
	c.TLSInsecure = skipVerify
	return c
}

// SetTLSServerName sets the ServerName to use for SNI when connecting to a remote TLS endpoint.
func (c *Config) SetTLSServerName(serverName string) *Config {
	if serverName != emptyString {
		c.TLSServerName = serverName
	}

	return c
}

// ProbedCipher holds the result of a single cipher suite probe.
type ProbedCipher struct {
	ID        uint16
	Name      string
	Protocol  string
	Insecure  bool
	Supported bool
}

// SetTLSInfoRequested sets whether to probe and print remote TLS protocol/cipher information.
func (c *Config) SetTLSInfoRequested(requested bool) *Config {
	c.TLSInfoRequested = requested
	return c
}
