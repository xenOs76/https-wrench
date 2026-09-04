package certinfo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/xenos76/https-wrench/internal/tlstest"
)

type (
	MockErrReader   struct{}
	MockInputReader struct{}
	mockReader      struct{}
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
	RSASamplePKCS8BrokenCertificate   = testdataDir + "/rsa-pkcs8-broken-crt.pem"
	RSASamplePKCS8ExpiredCertificate  = testdataDir + "/rsa-pkcs8-expired-crt.pem"

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

	defer func() {
		filesToDel := []string{
			RSACaCertKeyFile,
			RSACaCertFile,
			RSASampleCertFile,
			RSASampleCertKeyFile,
			RSASampleCertBundleFile,
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

func (MockErrReader) NoPasswordPrompt() bool { return true }

func (MockErrReader) ReadPassword(fd int) ([]byte, error) {
	return func(_ int) ([]byte, error) {
		return []byte{}, errors.New("mockErrReader: unable to read password")
	}(fd)
}

func (mockReader) ReadFile(name string) ([]byte, error) {
	return nil, fmt.Errorf("unable to read file %s", name)
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

	rsaSampleCertTpl := tlstest.Template{
		CN:          "RSA Testing Sample Certificate",
		Key:         RSASampleCertKey,
		CAKey:       RSACaCertKey,
		Parent:      RSACaCertParent,
		DNSNames:    []string{"example.com", "example.net", "example.de"},
		IPAddresses: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
	}

	RSASampleCertPEM, RSASampleCertParent, _ = tlstest.GenerateCert(
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

	RSASampleCertBundleFile, err = createTmpFileWithContent(
		testdataDir,
		"RSASampleCertBundle",
		[]byte(RSASampleCertPEMString+RSACaCertPEMString),
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

	rsaCaCertTpl := tlstest.Template{
		CN:   "RSA Testing CA",
		IsCA: true,
		Key:  RSACaCertKey,
	}
	RSACaCertPEM, RSACaCertParent, _ = tlstest.GenerateCert(
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

	if err = os.WriteFile(f.Name(), fileContent, 0o600); err != nil {
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
