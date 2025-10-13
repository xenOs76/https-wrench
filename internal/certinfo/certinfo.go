package certinfo

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

const (
	TLSTimeout      = 3 * time.Second
	CertExpWarnDays = 40
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
	TLSEndpointCertsValid   bool
	TLSServerName           string
	TLSInsecure             bool
}

var (
	certsBundle        []*x509.Certificate
	privKey            any
	tlsEndpoint        string
	TlsServerName      string
	TlsInsecure        bool
	privateKeyPwEnvVar = "CERTINFO_PKEY_PW"
)

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

func (c *CertinfoConfig) SetCaPoolFromFile(filePath string) error {
	if filePath != "" {
		caCertsPool, err := GetRootCertsFromFile(filePath)
		if err != nil {
			return err
		}
		c.CACertsPool = caCertsPool
	}
	return nil
}

func (c *CertinfoConfig) SetCertsFromFile(filePath string) error {
	if filePath != "" {
		certs, err := GetCertsFromBundle(filePath)
		if err != nil {
			return err
		}
		c.CertsBundle = certs
	}
	return nil
}

func (c *CertinfoConfig) SetPrivateKeyFromFile(filePath string) error {
	if filePath != "" {
		c.PrivKeyFilePath = filePath
		keyFromFile, err := GetKeyFromFile(c.PrivKeyFilePath)
		if err != nil {
			return err
		}
		c.PrivKey = keyFromFile
	}
	return nil
}

func (c *CertinfoConfig) SetTLSEndpoint(e string) error {
	if e != "" {
		c.TLSEndpoint = e
		eHost, ePort, err := net.SplitHostPort(c.TLSEndpoint)
		if err != nil {
			return fmt.Errorf("invalid TLS endpoint %q: %w", c.TLSEndpoint, err)
		}
		c.TLSEndpointHost = eHost
		c.TLSEndpointPort = ePort
		c.GetRemoteCerts()
	}
	return nil
}

func (c *CertinfoConfig) SetTLSInsecure(b bool) *CertinfoConfig {
	c.TLSInsecure = b
	return c
}

func (c *CertinfoConfig) SetTLSServerName(s string) *CertinfoConfig {
	if s != "" {
		c.TLSServerName = s
	}
	return c
}
