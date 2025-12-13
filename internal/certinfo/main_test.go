package certinfo

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
	"os"
	"testing"
	"time"
)

type (
	certificateTemplate struct {
		cn          string
		isCA        bool
		dnsNames    []string
		ipAddresses []net.IP
		key         *rsa.PrivateKey
		caKey       *rsa.PrivateKey
		parent      *x509.Certificate
	}

	MockErrReader struct{}

	MockInputReader struct{}
)

var (
	mockErrReader   MockErrReader
	mockInputReader MockInputReader

	testdataDir    = "testdata"
	unreadableFile = testdataDir + "/unreadable-file.txt"
	sampleTextFile = testdataDir + "/sample-text.txt"
	tempDir        string

	samplePrivateKeyPassword = "testpassword"

	RSASamplePKCS1PlaintextPrivateKey = testdataDir + "/rsa-pkcs1-plaintext-private-key.pem"
	RSASamplePKCS1EncryptedPrivateKey = testdataDir + "/rsa-pkcs1-encrypted-private-key.pem"
	RSASamplePKCS1EncBrokenPrivateKey = testdataDir + "/rsa-pkcs1-encrypted-broken-private-key.pem"
	RSASamplePKCS1Certificate         = testdataDir + "/rsa-pkcs1-crt.pem"

	RSASamplePKCS8PlaintextPrivateKey = testdataDir + "/rsa-pkcs8-plaintext-private-key.pem"
	RSASamplePKCS8EncryptedPrivateKey = testdataDir + "/rsa-pkcs8-encrypted-private-key.pem"
	RSASamplePKCS8EncBrokenPrivateKey = testdataDir + "/rsa-pkcs8-encrypted-broken-private-key.pem"
	RSASamplePKCS8Certificate         = testdataDir + "/rsa-pkcs8-crt.pem"

	ECDSASamplePlaintextPrivateKey = testdataDir + "/ecdsa-plaintext-private-key.pem"
	ECDSASampleEncryptedPrivateKey = testdataDir + "/ecdsa-encrypted-private-key.pem"
	ECDSASampleEncBrokenPrivateKey = testdataDir + "/ecdsa-encrypted-broken-private-key.pem"
	ECDSASampleCertificate         = testdataDir + "/ecdsa-crt.pem"

	ED25519SamplePlaintextPrivateKey = testdataDir + "/ed25519-plaintext-private-key.pem"
	ED25519SampleEncryptedPrivateKey = testdataDir + "/ed25519-encrypted-private-key.pem"
	ED25519SampleEncBrokenPrivateKey = testdataDir + "/ed25519-encrypted-broken-private-key.pem"
	ED25519SampleCertificate         = testdataDir + "/ed25519-crt.pem"

	systemCertPool *x509.CertPool
	caCertPool     *x509.CertPool
	RSACaCertPool  *x509.CertPool

	RSACaCertKey       *rsa.PrivateKey
	RSACaCertKeyPEM    []byte
	RSACaCertKeyFile   string
	RSACaCertPEM       []byte
	RSACaCertParent    *x509.Certificate
	RSACaCertPEMString string
	RSACaCertFile      string

	RSASampleCertKey        *rsa.PrivateKey
	RSASampleCertKeyPEM     []byte
	RSASampleCertKeyFile    string
	RSASampleCertPEM        []byte
	RSASampleCertParent     *x509.Certificate
	RSASampleCertPEMString  string
	RSASampleCertFile       string
	RSASampleCertBundleFile string
)

func TestMain(m *testing.M) {
	fmt.Printf("Certinfo TestMain - check test data dir: %s\n", testdataDir)

	if errDataDir := os.MkdirAll(testdataDir, 0o755); errDataDir != nil {
		panic(errDataDir)
	}

	// Cleanup (register early so panics in setup still clean up what was created)
	defer func() {
		filesToDel := []string{
			RSACaCertKeyFile,
			RSACaCertFile,
			RSASampleCertFile,
			RSASampleCertKeyFile,
		}
		for _, fileToDel := range filesToDel {
			err := os.Remove(fileToDel)
			if err != nil {
				fmt.Printf(
					"unable to remove file %s: %s",
					fileToDel,
					err.Error(),
				)
			}
		}
	}()

	systemCertPool, _ = x509.SystemCertPool()
	caCertPool = x509.NewCertPool()

	generateRSACaData()
	caCertPool.AppendCertsFromPEM(RSACaCertPEM)

	generateRSACertificateData()

	m.Run()
}

func (MockInputReader) ReadPassword(_ int) ([]byte, error) {
	return []byte(samplePrivateKeyPassword), nil
}

func (MockInputReader) ReadFile(name string) ([]byte, error) {
	return nil, fmt.Errorf("unable to read file %s", name)
}

func (MockErrReader) ReadFile(name string) ([]byte, error) {
	return nil, fmt.Errorf("unable to read file %s", name)
}

func (MockErrReader) ReadPassword(fd int) ([]byte, error) {
	return func(_ int) ([]byte, error) {
		return []byte{}, errors.New("mockErrReader: unable to read password")
	}(fd)
}

func generateRSACertificateData() {
	var err error

	// RSA Certificate
	RSASampleCertKey, _ = RSAGenerateKey(2048)
	RSASampleCertKeyPEM = RSAPrivateKeyToPEM(RSASampleCertKey)

	RSASampleCertKeyFile, err = createTmpFileWithContent(
		testdataDir,
		"RSASampleCertKey",
		RSASampleCertKeyPEM,
	)
	if err != nil {
		fmt.Println(err)
	}

	rsaSampleCertTpl := certificateTemplate{
		cn:          "RSA Testing Sample Certificate",
		isCA:        false,
		key:         RSASampleCertKey,
		caKey:       RSACaCertKey,
		parent:      RSACaCertParent,
		dnsNames:    []string{"example.com", "example.net", "example.de"},
		ipAddresses: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
	}

	RSASampleCertPEM, RSASampleCertParent, _ = GenerateCertificate(
		rsaSampleCertTpl,
	)
	RSASampleCertPEMString = string(RSASampleCertPEM)

	RSASampleCertFile, err = createTmpFileWithContent(
		testdataDir,
		"RSASampleCert",
		[]byte(RSASampleCertPEMString),
	)
	if err != nil {
		fmt.Print(err)
	}
}

func generateRSACaData() {
	var err error

	// RSA CA
	RSACaCertKey, _ = RSAGenerateKey(2048)
	RSACaCertKeyPEM = RSAPrivateKeyToPEM(RSACaCertKey)

	RSACaCertKeyFile, err = createTmpFileWithContent(
		testdataDir,
		"RSACaCertKey",
		RSACaCertKeyPEM,
	)
	if err != nil {
		fmt.Println(err)
	}

	rsaCaCertTpl := certificateTemplate{
		cn:   "RSA Testing CA",
		isCA: true,
		key:  RSACaCertKey,
	}
	RSACaCertPEM, RSACaCertParent, _ = GenerateCertificate(
		rsaCaCertTpl,
	)
	RSACaCertPEMString = string(RSACaCertPEM)

	RSACaCertPool = x509.NewCertPool()
	RSACaCertPool.AppendCertsFromPEM(RSACaCertPEM)

	RSACaCertFile, err = createTmpFileWithContent(
		testdataDir,
		"RSACaCert",
		[]byte(RSACaCertPEMString),
	)
	if err != nil {
		fmt.Print(err)
	}
}

// GenerateDemoCert takes as input a demoCertTemplate struct, creates a x509 Certificate
// and returns a PEM encoded version of the certificate, a pointer to the certificate and
// an error.
// The pointer can be used as parent in the creation of a new certificate linked to a self signed
// CA.
//
// Reference: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
func GenerateCertificate(tpl certificateTemplate) ([]byte, *x509.Certificate, error) {
	// Create a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Define template for non CA certificate
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: tpl.cn,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * 24 * time.Hour),
		IsCA:        false,
		DNSNames:    tpl.dnsNames,
		IPAddresses: tpl.ipAddresses,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certParent := tpl.parent
	signingKey := tpl.caKey

	// in case of CA cert we update the template with the proper fields
	// 	use the CA cert key for signing
	// and do not reference any previous parent Certificate
	if tpl.isCA {
		certParent = &template
		signingKey = tpl.key
		template = x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: tpl.cn,
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(1 * 24 * time.Hour),
			IsCA:      true,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader,
		&template, certParent, &tpl.key.PublicKey, signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode the certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// parse the DER encoded x509.Certificate
	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, certificate, nil
}

func createTmpFileWithContent(
	tempDir string,
	filePattern string,
	fileContent []byte,
) (filePath string, err error) {
	f, err := os.CreateTemp(tempDir, filePattern)
	if err != nil {
		return emptyString, err
	}

	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err = os.WriteFile(f.Name(), fileContent, 0644); err != nil {
		return emptyString, err
	}

	return f.Name(), nil
}

func RSAGenerateKey(bits int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return priv, nil
}

func RSAPrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   keyDER,
	}
	keyPEM := pem.EncodeToMemory(&keyBlock)

	return keyPEM
}
