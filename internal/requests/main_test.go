package requests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/xenos76/https-wrench/internal/tlstest"
)

var (
	testdataDir           = "testdata"
	systemCertPool        *x509.CertPool
	caCertKey             *rsa.PrivateKey
	caCertKeyFile         string
	caCertPEM             []byte
	caCertParent          *x509.Certificate
	caCertPEMString       string
	caCertPool            *x509.CertPool
	exampleCertKey        *rsa.PrivateKey
	exampleCertKeyFile    string
	exampleCertPEM        []byte
	exampleCertPEMString  string
	exampleCertFile       string
	exampleCertBundleFile string
	tempDir               string
)

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return priv, nil
}

func createTmpFileWithContent(tempDir string, filePattern string, fileContent []byte) (string, error) {
	f, err := os.CreateTemp(tempDir, filePattern)
	if err != nil {
		return emptyString, err
	}

	defer func() {
		err = errors.Join(err, f.Close())
	}()

	err = os.WriteFile(f.Name(), fileContent, 0o644)
	if err != nil {
		return emptyString, err
	}

	return f.Name(), nil
}

func printResponseBody(res *http.Response) {
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	fmt.Println(string(body))
}

//nolint:revive
func TestMain(m *testing.M) {
	fmt.Printf("Check test data dir: %s\n", testdataDir)

	if err := os.Mkdir(testdataDir, os.ModePerm); err != nil {
		fmt.Println(err)
	}

	fmt.Println("Creating demo CA cert")

	systemCertPool, _ = x509.SystemCertPool()

	caCertKey, _ := GenerateRSAKey(2048)

	caCertKeyDER := x509.MarshalPKCS1PrivateKey(caCertKey)
	caCertKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   caCertKeyDER,
	}
	caCertKeyPEM := pem.EncodeToMemory(&caCertKeyBlock)

	keyFile, err := createTmpFileWithContent(
		testdataDir, "caCertKey", caCertKeyPEM)
	if err != nil {
		fmt.Println(err)
	}

	caCertKeyFile = keyFile

	fmt.Printf("caCertKeyFile created at %s\n", caCertKeyFile)

	caCertTpl := tlstest.Template{CN: "Demo CA", IsCA: true, Key: caCertKey}
	caCertPEM, caCertParent, _ = tlstest.GenerateCert(caCertTpl)
	caCertPEMString = string(caCertPEM)
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	caCertFile, err := createTmpFileWithContent(
		testdataDir, "exampleCaCert", []byte(caCertPEMString))
	if err != nil {
		fmt.Print(err)
	}

	fmt.Printf("exampleCaCert file create at %s\n", caCertFile)

	certKey, err := GenerateRSAKey(2048)
	if err != nil {
		fmt.Print(err)
	}

	exampleCertKey = certKey
	exampleCertKeyDER := x509.MarshalPKCS1PrivateKey(exampleCertKey)
	exampleCertKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   exampleCertKeyDER,
	}
	exampleCertKeyPEM := pem.EncodeToMemory(&exampleCertKeyBlock)

	certKeyFile, err := createTmpFileWithContent(
		testdataDir, "exampleCertKey", exampleCertKeyPEM)
	if err != nil {
		fmt.Print(err)
	}

	exampleCertKeyFile = certKeyFile

	fmt.Printf("exampleCertKey file create at %s\n", exampleCertKeyFile)

	exampleCertTpl := tlstest.Template{
		CN:          "example.com",
		DNSNames:    []string{"example.com", "example.net", "example.de"},
		Key:         exampleCertKey,
		CAKey:       caCertKey,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
		Parent:      caCertParent,
	}

	exampleCertPEM, _, err = tlstest.GenerateCert(exampleCertTpl)
	if err != nil {
		fmt.Printf("error while creating exampleCert: %s\n", err)
	}

	exampleCertPEMString = string(exampleCertPEM)

	certFile, err := createTmpFileWithContent(
		"testdata", "exampleCert", exampleCertPEM)
	if err != nil {
		return
	}

	exampleCertFile = certFile

	fmt.Printf("exampleCert file created at %s\n", exampleCertFile)

	exampleCertBundleFile, err = createTmpFileWithContent(
		testdataDir,
		"exampleCertBundle",
		[]byte(exampleCertPEMString+caCertPEMString))
	if err != nil {
		return
	}

	fmt.Printf("exampleCertBundle file created at %s\n", exampleCertBundleFile)

	m.Run()

	// Cleanup
	//
	defer func() {
		filesToDel := []string{
			exampleCertFile,
			exampleCertBundleFile,
			exampleCertKeyFile,
			caCertKeyFile,
			caCertFile,
		}
		for _, fileToDel := range filesToDel {
			os.Remove(fileToDel)
		}
	}()
}

func TestHTTPSTestServer(t *testing.T) {
	tests := []struct {
		testname   string
		listenHost string
	}{
		{"localhostIPv4", "127.0.0.1"},
	}

	for _, tt := range tests {
		testname := tt.testname
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			ts, err := tlstest.NewServer(tlstest.ServerConfig{
				ListenHost:     tt.listenHost,
				ServerCertFile: exampleCertFile,
				ServerKeyFile:  exampleCertKeyFile,
			})
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(ts.Close)

			// fmt.Println("TestDemoHTTPSServer")
			// fmt.Print("Client URL: ")
			// fmt.Println(ts.URL)
			// fmt.Print("Listener address is: ")
			// fmt.Println(ts.Listener.Addr().String())

			tr := &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
				// InsecureSkipVerify: true,
			}}

			client := &http.Client{Transport: tr}

			res, err := client.Get(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			fmt.Printf("Resp StatusCode was: %v\n", res.StatusCode)
			assert.Equal(t, http.StatusOK, res.StatusCode)

			fmt.Printf("Req URL was: %v\n", res.Request.URL)
			assert.Equal(t, res.Request.URL.Scheme+"://"+res.Request.URL.Host,
				ts.URL)

			fmt.Println()
			fmt.Println("#### Respose Body ####")
			printResponseBody(res)
			fmt.Println()
		})
	}
}
