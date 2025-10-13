/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/certinfo"
)

var (
	tlsEndpoint   string
	tlsServerName string
	tlsInsecure   bool
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
		certinfoCfg, err := certinfo.NewCertinfoConfig()
		if err != nil {
			fmt.Printf("Error creating new Certinfo config: %s", err)
			return
		}

		certinfoCfg.SetTLSInsecure(tlsInsecure).SetTLSServerName(tlsServerName)

		if err := certinfoCfg.SetCaPoolFromFile(viper.GetString("ca-bundle")); err != nil {
			fmt.Printf("Error importing CA Certificate bundle from file: %s", err)
		}

		if err := certinfoCfg.SetCertsFromFile(viper.GetString("cert-bundle")); err != nil {
			fmt.Printf("Error importing Certificate bundle from file: %s", err)
		}

		if err := certinfoCfg.SetTLSEndpoint(tlsEndpoint); err != nil {
			fmt.Printf("Error setting TLS endpoint: %s", err)
		}

		if err := certinfoCfg.SetPrivateKeyFromFile(viper.GetString("key-file")); err != nil {
			fmt.Printf("Error importing key from file: %s", err)
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
