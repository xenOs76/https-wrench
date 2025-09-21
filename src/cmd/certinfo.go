/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/
package cmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	// "github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

const (
	certinfoTlsPort    string        = "443"
	certinfoTlsTimeout time.Duration = 3
)

type CertinfoConfig struct {
	CACerts                 *x509.CertPool
	CertsBundle             []*x509.Certificate
	CertsBundleFromKey      bool
	PrivKey                 crypto.PrivateKey
	TlsEndpointHost         string
	TlsEndpointPort         string
	TlsEndpointCerts        []*x509.Certificate
	TlsEndpointCertsFromKey bool
	TlsEndpointCertsValid   bool
	TlsServerName           string
	TlsInsecure             bool
}

var (
	certsBundle   []*x509.Certificate
	privKey       any
	tlsEndpoint   string
	tlsServerName string
	tlsInsecure   bool
)

var certinfoCmd = &cobra.Command{
	Use:   "certinfo",
	Short: "Show info about PEM certificates and keys",
	Long:  "Show info about PEM certificates and keys",
	Run: func(cmd *cobra.Command, args []string) {

		certinfoCfg := CertinfoConfig{TlsInsecure: tlsInsecure, TlsServerName: tlsServerName}

		caCerts, err := x509.SystemCertPool()
		if err != nil {
			fmt.Printf("Error creating system cert pool: %s", err)
			os.Exit(1)
		}
		certinfoCfg.CACerts = caCerts

		if caBundlePath != "" {
			caCerts, err := getRootCertsFromFile(caBundlePath)
			if err != nil {
				fmt.Printf("Error importing CA Certificate bundle from file: %s", err)
				os.Exit(1)
			}
			certinfoCfg.CACerts = caCerts
		}

		if certBundlePath != "" {
			certsFromBundle, err := getCertsFromBundle(certBundlePath)
			if err != nil {
				fmt.Printf("Error importing Certificate bundle from file: %s", err)
				os.Exit(1)
			}
			certinfoCfg.CertsBundle = certsFromBundle

		}

		if tlsEndpoint != "" {
			endpointHost, endpointPort, err := net.SplitHostPort(tlsEndpoint)
			if err != nil {
				fmt.Printf("Error parsing TLS endpoint url: %s", err)
				os.Exit(1)
			}
			certinfoCfg.TlsEndpointHost = endpointHost
			certinfoCfg.TlsEndpointPort = endpointPort
			certinfoCfg.GetRemoteCerts()

		}

		if keyFilePath != "" {
			keyFromFile, err := getKeyFromFile(keyFilePath)
			if err != nil {
				fmt.Printf("Error importing key from file: %s", err)
				os.Exit(1)
			}
			certinfoCfg.PrivKey = keyFromFile
		}

		// dump.Print(certinfoCfg)
		certinfoCfg.PrintData()

	},
}

func init() {
	certinfoCmd.Flags().StringVar(&tlsEndpoint, "tls-endpoint", "", "TLS enabled endpoint exposing certificates to fetch. Forms: 'host:port', '[host]:port'. A literal IPv6 address must be enclosed in square brackets, as in '[::1]:80'")
	certinfoCmd.Flags().StringVar(&tlsServerName, "tls-servername", "", "ServerName to use when fetching data from an SNI enabled TLS endpoint")
	certinfoCmd.Flags().BoolVar(&tlsInsecure, "tls-insecure", false, "Skip certificate validation when connecting to a TLS endpoint")
	rootCmd.AddCommand(certinfoCmd)
}

func (c *CertinfoConfig) PrintData() {

	ks := styleItemKey.PaddingBottom(0).PaddingTop(1).PaddingLeft(1)

	fmt.Println()
	fmt.Println(lgSprintf(styleCmd, "Certinfo"))
	fmt.Println()

	if c.PrivKey != nil {
		fmt.Println(lgSprintf(ks, "PrivateKey"))
		printKeyInfoStyle(c.PrivKey)
	}

	if len(c.CertsBundle) > 0 {
		fmt.Println(lgSprintf(ks, "Bundle certs"))
		CertsToTables(c.CertsBundle)
		if c.PrivKey != nil {
			certMatch, err := certMatchPrivateKey(c.CertsBundle[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}
			fmt.Println(lgSprintf(styleCertKeyP4.Bold(true), "PrivateKey match: %v", boolStyle(certMatch)))
		}
	}

	if len(c.TlsEndpointCerts) > 0 {
		fmt.Println(lgSprintf(ks, "TLSEndpoint certs"))
		CertsToTables(c.TlsEndpointCerts)
		if c.PrivKey != nil {
			tlsMatch, err := certMatchPrivateKey(c.TlsEndpointCerts[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}
			fmt.Println(lgSprintf(styleCertKeyP4.Bold(true), "PrivateKey match: %v", boolStyle(tlsMatch)))
		}
	}
}

func (c *CertinfoConfig) GetRemoteCerts() {

	tlsConfig := &tls.Config{RootCAs: c.CACerts, InsecureSkipVerify: c.TlsInsecure}

	if c.TlsServerName != "" {
		tlsConfig.ServerName = c.TlsServerName
	}

	serverAddr := net.JoinHostPort(c.TlsEndpointHost, c.TlsEndpointPort)

	dialer := &net.Dialer{
		Timeout: certinfoTlsTimeout * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	c.TlsEndpointCerts = cs.PeerCertificates

	opts := x509.VerifyOptions{
		DNSName:       c.TlsServerName,
		Roots:         c.CACerts,
		Intermediates: x509.NewCertPool(),
	}

	for _, ic := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(ic)
	}

	if _, err := c.TlsEndpointCerts[0].Verify(opts); err != nil {
		fmt.Println(err)
	} else {
		c.TlsEndpointCertsValid = true
	}
}
