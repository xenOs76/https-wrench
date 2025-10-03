/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/
package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	// "github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

const (
	certinfoTlsPort         string        = "443"
	certinfoTlsTimeout      time.Duration = 3
	certinfoCertExpWarnDays               = 40
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
	certsBundle        []*x509.Certificate
	privKey            any
	tlsEndpoint        string
	tlsServerName      string
	tlsInsecure        bool
	privateKeyPwEnvVar string = "CERTINFO_PKEY_PW"
)

var certinfoCmd = &cobra.Command{
	Use:   "certinfo",
	Short: "Show info about PEM certificates and keys",
	Long: `Show info about PEM certificates and keys.
Can fetch certificates from a TLS endpoint, read from a PEM bundle file, and check if a private 
key matches any of the certificates.
The certificates can be verified against the system root CAs or a custom CA bundle file. 
The validation can be skipped.
If the private key is password protected, the password can be provided via the CERTINFO_PKEY_PW 
environment variable or will be prompted on stdin.
Examples:
  certinfo --tls-endpoint example.com:443
  certinfo --cert-bundle ./bundle.pem --key-file ./key.pem
  certinfo --cert-bundle ./bundle.pem
  certinfo --key-file ./key.pem
  certinfo --tls-endpoint example.com:443 --key-file ./key.pem
  certinfo --tls-endpoint example.com:443 --cert-bundle ./bundle.pem --key-file ./key.pem
  certinfo --tls-endpoint example.com:443 --tls-servername www.example.com
  certinfo --tls-endpoint [2001:db8::1]:443 --tls-insecure
  certinfo --ca-bundle ./ca-bundle.pem --tls-endpoint example.com:443
  certinfo --ca-bundle ./ca-bundle.pem --cert-bundle ./bundle.pem --key-file ./key.pem	
`,
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
	certinfoCmd.Flags().StringVar(&tlsEndpoint,
		"tls-endpoint",
		"",
		`TLS enabled endpoint exposing certificates to fetch. 
Forms: 'host:port', '[host]:port'. 
IPv6 addresses must be enclosed in square brackets, as in '[::1]:80'`)
	certinfoCmd.Flags().StringVar(&tlsServerName,
		"tls-servername",
		"",
		"ServerName to use when connecting to an SNI enabled TLS endpoint")
	certinfoCmd.Flags().BoolVar(&tlsInsecure,
		"tls-insecure",
		false,
		"Skip certificate validation when connecting to a TLS endpoint")
	rootCmd.AddCommand(certinfoCmd)
}
