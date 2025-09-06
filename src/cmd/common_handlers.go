package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
)

func getRootCertsFromFile(caBundlePath string) (*x509.CertPool, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certsFromFile, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file: %v", err)
	}
	if ok := rootCAs.AppendCertsFromPEM(certsFromFile); !ok {
		fmt.Println("Certs from file not appended, using system certs only")
	}
	return rootCAs, nil
}

func getRootCertsFromString(caBundleString string) (*x509.CertPool, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caBundleString != "" {
		if ok := rootCAs.AppendCertsFromPEM([]byte(caBundleString)); !ok {
			return nil, fmt.Errorf("no valid certs in caBundle config string")
		}
	}
	return rootCAs, nil
}
