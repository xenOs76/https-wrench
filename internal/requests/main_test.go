package requests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/pires/go-proxyproto"
)

type demoCertTemplate struct {
	cn          string
	isCA        bool
	dnsNames    []string
	ipAddresses []net.IP
	key         *rsa.PrivateKey
	caKey       *rsa.PrivateKey
	parent      *x509.Certificate
}

type demoHttpServerData struct {
	serverAddr        string
	proxyprotoEnabled bool
	serverName        string
	tlsCipherSuites   []uint16
	tlsMaxVersion     uint16
}

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

// GenerateDemoCert takes as input a demoCertTemplate struct, creates a x509 Certificate
// and returns a PEM encoded version of the certificate, a pointer to the certificate and
// an error.
// The pointer can be used as parent in the creation of a new certificate linked to a self signed
// CA.
//
// Reference: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
func GenerateDemoCert(tpl demoCertTemplate) ([]byte, *x509.Certificate, error) {
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
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certParent := tpl.parent
	signingKey := tpl.caKey

	// in case of CA cert we udpate the template with the proper fields
	// 	use the CA cert key for signing
	// and do not reference any previuous parent Certificate
	if tpl.isCA {
		certParent = &template
		signingKey = tpl.key
		template = x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: tpl.cn,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(1 * 24 * time.Hour),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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

	err = os.WriteFile(f.Name(), fileContent, 0644)
	if err != nil {
		return emptyString, err
	}

	return f.Name(), nil
}

func printResponseBody(res *http.Response) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	fmt.Println(string(body))
}

func NewHTTPSTestServer(data demoHttpServerData) (*httptest.Server, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DemoHTTPSServer Handler - client output\n")
		fmt.Fprint(w, "Host requested: ", r.Host, "\n")

		fmt.Println("DemoHTTPSServer Handler - shell output")
	})

	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = true

	// fmt.Println("Inside NewDemoHTTPSServer()")

	if data.serverAddr != emptyString && !data.proxyprotoEnabled {
		listener, err := net.Listen("tcp", data.serverAddr)
		if err != nil {
			fmt.Println("Error creating listener:", err)
		}

		ts.Listener = listener
	}

	if data.serverAddr != emptyString && data.proxyprotoEnabled {
		ln, err := net.Listen("tcp", data.serverAddr)
		if err != nil {
			panic(err)
		}

		proxyListener := &proxyproto.Listener{
			Listener:          ln,
			ReadHeaderTimeout: 10 * time.Second,
		}

		ts.Listener = proxyListener
	}

	cert, err := tls.LoadX509KeyPair(
		exampleCertFile,
		exampleCertKeyFile,
	)
	if err != nil {
		return nil, err
	}

	// Set default TLS CipherSuites to TLS 1.3 cipher suites
	// https://pkg.go.dev/crypto/tls#pkg-constants
	tlsCipherSuites := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	if len(data.tlsCipherSuites) > 0 {
		tlsCipherSuites = data.tlsCipherSuites
	}

	// Set default TLS MaxVersion to 1.3
	var tlsMaxVersion uint16 = tls.VersionTLS13

	if data.tlsMaxVersion > 0 {
		tlsMaxVersion = data.tlsMaxVersion
	}

	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: tlsCipherSuites,
		MaxVersion:   tlsMaxVersion,
	}

	ts.StartTLS()

	return ts, nil
}

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

	caCertTpl := demoCertTemplate{cn: "Demo CA", isCA: true, key: caCertKey}
	caCertPEM, caCertParent, _ = GenerateDemoCert(caCertTpl)
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

	exampleCertTpl := demoCertTemplate{
		cn:          "example.com",
		isCA:        false,
		dnsNames:    []string{"example.com", "example.net", "example.de"},
		key:         exampleCertKey,
		caKey:       caCertKey,
		ipAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
		parent:      caCertParent,
	}

	exampleCertPEM, _, err = GenerateDemoCert(exampleCertTpl)
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
		serverAddr string
	}{
		{"localhostIPv4", "127.0.0.1:55667"},
	}

	for _, tt := range tests {
		testname := tt.testname
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			httpSrvData := demoHttpServerData{serverAddr: tt.serverAddr}
			// httpSrvData := demoHttpServerData{}

			ts, err := NewHTTPSTestServer(httpSrvData)
			if err != nil {
				t.Fatal(err)
			}

			defer ts.Close()

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
