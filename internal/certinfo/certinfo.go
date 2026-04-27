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
	TLSTimeout         = 3 * time.Second
	CertExpWarnDays    = 40
	privateKeyPwEnvVar = "CERTINFO_PKEY_PW"
	emptyString        = ""
)

// CertinfoConfig holds the configuration and results for certificate and key information retrieval.
type CertinfoConfig struct {
	CACertsPool             *x509.CertPool
	CACertsFilePath         string
	CertsBundle             []*x509.Certificate
	CertsBundleFilePath     string
	CertsBundleFromKey      bool
	PrivKey                 crypto.PrivateKey
	PrivKeyFilePath         string
	TLSEndpoint             string
	TLSEndpointHost         string
	TLSEndpointPort         string
	TLSEndpointCerts        []*x509.Certificate
	TLSEndpointCertsFromKey bool
	TLSServerName           string
	TLSInsecure             bool
}

// Reader defines an interface for reading files and passwords.
type (
	Reader interface {
		ReadFile(name string) ([]byte, error)
		ReadPassword(fd int) ([]byte, error)
	}

	// InputReader implements the Reader interface using standard OS calls.
	InputReader struct{}
)

var (
	//nolint:revive
	TLSServerName string
	TLSInsecure   bool
	inputReader   InputReader
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

// NewCertinfoConfig creates a new CertinfoConfig with the system's default certificate pool.
func NewCertinfoConfig() (*CertinfoConfig, error) {
	defaultCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	c := CertinfoConfig{
		CACertsPool: defaultCertPool,
	}

	return &c, nil
}

// SetCaPoolFromFile loads a CA certificate pool from the specified PEM bundle file.
func (c *CertinfoConfig) SetCaPoolFromFile(filePath string, fileReader Reader) error {
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
func (c *CertinfoConfig) SetCertsFromFile(filePath string, fileReader Reader) error {
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
// If the key is encrypted, it will attempt to retrieve the passphrase from an environment variable or interactive prompt.
func (c *CertinfoConfig) SetPrivateKeyFromFile(
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
func (c *CertinfoConfig) SetTLSEndpoint(hostport string) error {
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
func (c *CertinfoConfig) SetTLSInsecure(skipVerify bool) *CertinfoConfig {
	c.TLSInsecure = skipVerify
	return c
}

// SetTLSServerName sets the ServerName to use for SNI when connecting to a remote TLS endpoint.
func (c *CertinfoConfig) SetTLSServerName(serverName string) *CertinfoConfig {
	if serverName != emptyString {
		c.TLSServerName = serverName
	}

	return c
}
