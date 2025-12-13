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
	"time"

	"github.com/youmark/pkcs8"
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

func GetRootCertsFromFile(caBundlePath string, fileReader Reader) (*x509.CertPool, error) {
	if caBundlePath == emptyString {
		return nil, errors.New("empty string provided as caBundlePath")
	}

	certsFromFile, err := fileReader.ReadFile(caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file: %w", err)
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(certsFromFile); !ok {
		return nil, errors.New("unable to create CertPool from file")
	}

	return rootCAPool, nil
}

func GetRootCertsFromString(caBundleString string) (*x509.CertPool, error) {
	if caBundleString == emptyString {
		return nil, errors.New("empty string provided as caBundleString")
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM([]byte(caBundleString)); !ok {
		return nil, errors.New("no valid certs in caBundle config string")
	}

	return rootCAPool, nil
}

func GetCertsFromBundle(certBundlePath string, fileReader Reader) ([]*x509.Certificate, error) {
	if certBundlePath == emptyString {
		return nil, errors.New("empty string provided as caBundlePath")
	}

	certPEM, err := fileReader.ReadFile(certBundlePath)
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

// IsPrivateKeyEncrypted checks if the given PEM key is encrypted.
// It returns true if encrypted, false otherwise, and an error if decoding fails.
func IsPrivateKeyEncrypted(key []byte) (bool, error) {
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return false, errors.New("failed to decode PEM")
	}

	switch keyBlock.Type {
	case "ENCRYPTED PRIVATE KEY": // PKCS8 RSA, ED25519
		return true, nil
	case "EC PRIVATE KEY", "RSA PRIVATE KEY": // EC and PKCS1 RSA, encrypted or not
		_, hasDEK := keyBlock.Headers["DEK-Info"] // if encrypted, DEK-Info header exists
		return hasDEK, nil
	default:
		return false, fmt.Errorf("unrecognized private key type: %s", keyBlock.Type)
	}
}

func getPassphraseIfNeeded(isEncrypted bool, pwEnvKey string, pwReader Reader) ([]byte, error) {
	if !isEncrypted {
		return nil, nil
	}

	pkeyEnvPw := os.Getenv(pwEnvKey)
	if pkeyEnvPw != "" {
		return []byte(pkeyEnvPw), nil
	}

	fmt.Print("Private key is encrypted, please enter passphrase: ")

	pw, trErr := pwReader.ReadPassword(int(os.Stdin.Fd()))

	fmt.Println()

	if trErr != nil {
		return nil, fmt.Errorf("error reading passphrase: %w", trErr)
	}

	return pw, nil
}

// ParsePrivateKey parses a PEM-encoded private key and returns it as a crypto.PrivateKey.
//
// Supported formats:
//
// - PKCS#8 ("BEGIN PRIVATE KEY" / "BEGIN ENCRYPTED PRIVATE KEY") — decrypted with github.com/youmark/pkcs8
//
// - PKCS#1 RSA ("BEGIN RSA PRIVATE KEY") — cleartext or PEM-encrypted (x509.DecryptPEMBlock)
//
// - EC private keys ("BEGIN EC PRIVATE KEY") — cleartext or certain PKCS#8-encrypted ECDSA keys
//
// If the PEM is encrypted the function will try to read the passphrase from the environment
// variable named by pwEnvKey; if that is empty it will prompt the user interactively.
//
// The function returns a descriptive error if the PEM cannot be decoded, decryption/parsing fails,
// or the key format is unsupported.
func ParsePrivateKey(keyPEM []byte, pwEnvKey string, pwReader Reader) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode PEM")
	}

	isEncrypted, _ := IsPrivateKeyEncrypted(keyPEM)

	pass, err := getPassphraseIfNeeded(isEncrypted, pwEnvKey, pwReader)
	if err != nil {
		return nil, err
	}

	switch keyBlock.Type {
	case "ENCRYPTED PRIVATE KEY": // RSA PKCS8, ED25519
		priv, err := pkcs8.ParsePKCS8PrivateKey(keyBlock.Bytes, pass)
		if err != nil {
			return nil, fmt.Errorf("PKCS8 decryption failed: %w", err)
		}

		return priv, nil
	default: // RSA PKCS1, EC
		if isEncrypted {
			decryptedDERBytes, err := x509.DecryptPEMBlock(keyBlock, pass)
			if err != nil {
				return nil, fmt.Errorf("PEM block decryption failed: %w", err)
			}

			keyBlock.Bytes = decryptedDERBytes
		}
	}

	// Try PKCS8
	if pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil { // NO errors, returning the key
		return pkcs8Key, nil
	}
	// Try PKCS1 RSA
	if rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil { // NO errors, returning the key
		return rsaKey, nil
	}
	// Try EC
	if ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil { // NO errors, returning the key
		return ecKey, nil
	}

	return nil, errors.New("unsupported key format or invalid password")
}

func GetKeyFromFile(keyFilePath string, keyPwEnvVar string, inputReader Reader) (crypto.PrivateKey, error) {
	if keyFilePath == emptyString {
		return nil, errors.New("empty string provided as keyFilePath")
	}

	keyPEM, err := inputReader.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKey(
		keyPEM,
		keyPwEnvVar,
		inputReader,
	)
	if err != nil {
		return nil, err
	}

	return key, nil
}
