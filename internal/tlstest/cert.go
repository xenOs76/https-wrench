// Package tlstest provides TLS certificates and HTTPS test servers for tests.
package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const certValidity = 24 * time.Hour

// Template holds the fields needed to issue a test CA or leaf certificate.
type Template struct {
	// CN is the certificate subject Common Name.
	CN string
	// IsCA issues a self-signed CA when true; otherwise a leaf signed by Parent/CAKey.
	IsCA bool
	// DNSNames are SAN DNS names for a leaf certificate.
	DNSNames []string
	// IPAddresses are SAN IP addresses for a leaf certificate.
	IPAddresses []net.IP
	// Key is the RSA private key whose public key is embedded in the certificate.
	Key *rsa.PrivateKey
	// CAKey signs a leaf certificate. Ignored when IsCA is true.
	CAKey *rsa.PrivateKey
	// Parent is the issuing CA certificate for a leaf. Ignored when IsCA is true.
	Parent *x509.Certificate
}

// GenerateCert creates a PEM-encoded x509 certificate from tpl.
// The returned *x509.Certificate can be used as Parent when issuing a leaf.
func GenerateCert(tpl Template) ([]byte, *x509.Certificate, error) {
	if tpl.Key == nil {
		return nil, nil, errors.New("missing certificate private key")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(certValidity)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: tpl.CN,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        false,
		DNSNames:    tpl.DNSNames,
		IPAddresses: tpl.IPAddresses,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certParent := tpl.Parent
	signingKey := tpl.CAKey

	if tpl.IsCA {
		signingKey = tpl.Key
		template = x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: tpl.CN,
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			IsCA:      true,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		certParent = &template
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		certParent,
		&tpl.Key.PublicKey,
		signingKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, certificate, nil
}
