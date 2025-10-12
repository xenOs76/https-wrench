package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/youmark/pkcs8"
	"golang.org/x/term"
)

func PrintCertInfo(cert *x509.Certificate, depth int) {
	prefix := ""
	for range depth {
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

// Check if the first Certificate from a slice has been created with the
// PrivateKey passed as argument.
func certsFromPrivateKey(c []*x509.Certificate, key crypto.PrivateKey) (bool, error) {
	if len(c) == 0 {
		return false, errors.New("empty Certificate slice provided")
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
		return false, errors.New("unsupported public key type in certificate")
	}

	return match, nil
}

// Check if the PublicKey of a Certificate matches the PrivateKey.
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
		return false, errors.New("unsupported public key type in certificate")
	}

	return match, nil
}

// TODO: add comment explaining why returning an empty pool in case of empty string
func GetRootCertsFromFile(caBundlePath string) (*x509.CertPool, error) {
	rootCAPool := x509.NewCertPool()

	certsFromFile, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file: %w", err)
	}

	if ok := rootCAPool.AppendCertsFromPEM(certsFromFile); !ok {
		fmt.Println("Certs from file not appended, using system certs only")
	}

	return rootCAPool, nil
}

func GetRootCertsFromString(caBundleString string) (*x509.CertPool, error) {
	rootCAPool := x509.NewCertPool()
	if caBundleString != "" {
		if ok := rootCAPool.AppendCertsFromPEM([]byte(caBundleString)); !ok {
			return nil, errors.New("no valid certs in caBundle config string")
		}
	}

	return rootCAPool, nil
}

func GetCertsFromBundle(certBundlePath string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certBundlePath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file: %w", err)
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
			return nil, fmt.Errorf("error parsing certificate: %w", err)
		}

		certs = append(certs, c)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in file %s", certBundlePath)
	}

	return certs, nil
}

// Read a private key from file.
//
// If the key is encrypted look for a passphrase in the environment variable matching the value of
// privateKeyPwEnvVar, otherwise prompt for it on stdin.
//
// Evaluated key forms are:
//
// * PKCS #8, ASN.1 DER (encoded in PEM blocks of type "PRIVATE KEY")
//
// * RSA PKCS #1, ASN.1 DER (encoded in PEM blocks of type "RSA PRIVATE KEY")
//
// * EC private key in SEC 1, ASN.1 DER (encoded in PEM blocks of type "EC PRIVATE KEY").
func GetKeyFromFile(keyFilePath string) (crypto.PrivateKey, error) {
	pkcs8Encrypted := false
	pkcs1Encrypted := false
	pkeyEnvPw := os.Getenv(privateKeyPwEnvVar)
	pass := []byte{}

	keyPEM, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	pkcs8EncRE := regexp.MustCompile(`\sENCRYPTED\sPRIVATE\sKEY`)
	if pkcs8EncRE.Match(keyPEM) {
		pkcs8Encrypted = true
	}

	pkcs1EncRE := regexp.MustCompile(`4,ENCRYPTED`)
	if pkcs1EncRE.Match(keyPEM) {
		pkcs1Encrypted = true
	}

	if (pkeyEnvPw != "") && (pkcs1Encrypted || pkcs8Encrypted) {
		pass = []byte(pkeyEnvPw)
	}

	if (pkeyEnvPw == "") && (pkcs1Encrypted || pkcs8Encrypted) {
		fmt.Print("Private key is encrypted, please enter passphrase:")

		pw, trErr := term.ReadPassword(int(os.Stdin.Fd()))
		if trErr != nil {
			return nil, fmt.Errorf("error reading passphrase: %w", trErr)
		}

		pass = pw
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key from %s", keyFilePath)
	}

	var pkcs8PrivKey any
	if pkcs8Encrypted {
		pkcs8PrivKey, err = pkcs8.ParsePKCS8PrivateKey(keyBlock.Bytes, pass)
		if err != nil {
			return nil, fmt.Errorf("error decrypting PKCS8 private key: %w", err)
		}

		return pkcs8PrivKey, nil
	}

	var keyDER []byte
	if pkcs1Encrypted {
		keyDER, err = x509.DecryptPEMBlock(keyBlock, pass)
		if err != nil {
			return nil, fmt.Errorf("error decrypting PKCS1 private key: %w", err)
		}

		keyBlock.Bytes = keyDER
	}

	pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if pkcs8Err == nil {
		return pkcs8Key, nil
	}

	rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if pkcs1Err == nil {
		return rsaKey, nil
	}

	ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes)
	if ecErr == nil {
		return ecKey, nil
	}

	err = ecErr

	return nil, fmt.Errorf("error parsing private key: %w", err)
}
