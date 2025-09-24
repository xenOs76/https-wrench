package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func printCertInfo(cert *x509.Certificate, depth int) {
	prefix := ""
	for i := 0; i < depth; i++ {
		prefix += "  "
	}
	fmt.Printf("%sSubject: %s\n", prefix, cert.Subject)
	fmt.Printf("%sIssuer:  %s\n", prefix, cert.Issuer)
	fmt.Printf("%sValid From: %s\n", prefix, cert.NotBefore.Format(time.RFC1123))
	fmt.Printf("%sValid To:   %s\n", prefix, cert.NotAfter.Format(time.RFC1123))
	fmt.Printf("%sDNS Names: %v\n", prefix, cert.DNSNames)
	fmt.Printf("%sIs CA: %v\n", prefix, cert.IsCA)
	fmt.Printf("%sSerial Number: %s\n", prefix, cert.SerialNumber)
	fmt.Printf("%sPublic Key Algorithm: %s\n", prefix, cert.PublicKeyAlgorithm)
	fmt.Printf("%sSignature Algorithm: %s\n", prefix, cert.SignatureAlgorithm)
	fmt.Println()
}

func printKeyInfo(privKey crypto.PrivateKey) {
	fmt.Println("----- Private Key Info -----")
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		fmt.Println("Type: RSA")
		fmt.Printf("Key Size: %d bits\n", k.N.BitLen())
	case *ecdsa.PrivateKey:
		fmt.Println("Type: ECDSA")
		fmt.Printf("Curve: %s\n", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		fmt.Println("Type: Ed25519")
		fmt.Printf("Key Size: %d bytes\n", len(k))
	default:
		fmt.Println("Unknown key type")
	}
	fmt.Println()
}

// Check if the first Certificate from a slice has been created with the PrivateKey passed as argument
func certsFromPrivateKey(c []*x509.Certificate, key crypto.PrivateKey) (bool, error) {
	if len(c) == 0 {
		return false, fmt.Errorf("empty Certificate slice provided")
	}

	match := false
	switch pub := c[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if k, ok := key.(*rsa.PrivateKey); ok && k.PublicKey.N.Cmp(pub.N) == 0 && k.PublicKey.E == pub.E {
			match = true
		}
	case *ecdsa.PublicKey:
		if k, ok := key.(*ecdsa.PrivateKey); ok && k.PublicKey.X.Cmp(pub.X) == 0 && k.PublicKey.Y.Cmp(pub.Y) == 0 {
			match = true
		}
	case ed25519.PublicKey:
		if k, ok := key.(ed25519.PrivateKey); ok && k.Public().(ed25519.PublicKey).Equal(pub) {
			match = true
		}
	default:
		return false, fmt.Errorf("unsupported public key type in certificate")
	}
	return match, nil
}

// Check if the PublicKey of a Certificate matches the PrivateKey
func certMatchPrivateKey(cert *x509.Certificate, key crypto.PrivateKey) (bool, error) {
	if cert == nil {
		return false, nil
	}

	if key == nil {
		return false, nil
	}

	match := false
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k, ok := key.(*rsa.PrivateKey); ok && k.PublicKey.N.Cmp(pub.N) == 0 && k.PublicKey.E == pub.E {
			match = true
		}
	case *ecdsa.PublicKey:
		if k, ok := key.(*ecdsa.PrivateKey); ok && k.PublicKey.X.Cmp(pub.X) == 0 && k.PublicKey.Y.Cmp(pub.Y) == 0 {
			match = true
		}
	case ed25519.PublicKey:
		if k, ok := key.(ed25519.PrivateKey); ok && k.Public().(ed25519.PublicKey).Equal(pub) {
			match = true
		}
	default:
		return false, fmt.Errorf("unsupported public key type in certificate")
	}
	return match, nil
}

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

func getCertsFromBundle(certBundlePath string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certBundlePath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file: %s", err)
	}

	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in file %s", certBundlePath)
	}
	return certs, nil
}

// Read an unecrypted private key from file.
//
// Evaluated key forms are:
//
// * PKCS #8, ASN.1 DER (encoded in PEM blocks of type "PRIVATE KEY")
//
// * RSA PKCS #1, ASN.1 DER (encoded in PEM blocks of type "RSA PRIVATE KEY")
//
// * EC private key in SEC 1, ASN.1 DER (encoded in PEM blocks of type "EC PRIVATE KEY")
func getKeyFromFile(keyFilePath string) (crypto.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key from %s", keyFilePath)
	}

	pkcs8Key, PKCS8err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if PKCS8err == nil {
		return pkcs8Key, nil
	}
	err = PKCS8err

	rsaKey, PKCS1err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if PKCS1err == nil {
		return rsaKey, nil
	}
	err = PKCS1err

	ecKey, ECerr := x509.ParseECPrivateKey(keyBlock.Bytes)
	if ECerr == nil {
		return ecKey, nil
	}
	err = ECerr

	return nil, fmt.Errorf("error parsing private key: %v", err)
}
