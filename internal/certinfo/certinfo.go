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

type (
	Reader interface {
		ReadFile(name string) ([]byte, error)
		ReadPassword(fd int) ([]byte, error)
	}

	InputReader struct{}
)

var (
	TlsServerName string
	TlsInsecure   bool
	inputReader   InputReader
)

func (InputReader) ReadFile(name string) ([]byte, error) {
	file, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (InputReader) ReadPassword(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

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

func (c *CertinfoConfig) SetTLSEndpoint(hostport string) error {
	if hostport != emptyString {
		eHost, ePort, err := net.SplitHostPort(hostport)
		if err != nil {
			return fmt.Errorf("invalid TLS endpoint %q: %w", c.TLSEndpoint, err)
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

func (c *CertinfoConfig) SetTLSInsecure(skipVerify bool) *CertinfoConfig {
	c.TLSInsecure = skipVerify
	return c
}

func (c *CertinfoConfig) SetTLSServerName(serverName string) *CertinfoConfig {
	if serverName != emptyString {
		c.TLSServerName = serverName
	}

	return c
}
