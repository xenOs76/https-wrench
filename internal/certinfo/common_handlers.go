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

func readFile(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return bytes, nil
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

func getPassphraseIfNeeded(isEncrypted bool, pwEnvKey string) ([]byte, error) {
	if !isEncrypted {
		return nil, nil
	}
	pkeyEnvPw := os.Getenv(pwEnvKey)
	if pkeyEnvPw != "" {
		return []byte(pkeyEnvPw), nil
	}
	fmt.Print("Private key is encrypted, please enter passphrase: ")
	pw, trErr := term.ReadPassword(int(os.Stdin.Fd()))
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
func ParsePrivateKey(keyPEM []byte, pwEnvKey string) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode PEM")
	}

	isEncrypted, _ := IsPrivateKeyEncrypted(keyPEM)

	pass, err := getPassphraseIfNeeded(isEncrypted, pwEnvKey)
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

func GetKeyFromFile(keyFilePath string) (crypto.PrivateKey, error) {
	keyPEM, err := readFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKey(keyPEM, privateKeyPwEnvVar)
	if err != nil {
		return nil, err
	}
	return key, nil
}
