/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/certinfo"
)

var (
	tlsEndpoint   string
	tlsServerName string
	tlsInsecure   bool
	keyPwEnvVar   = "CERTINFO_PKEY_PW"
)

var certinfoCmd = &cobra.Command{
	Use:   "certinfo",
	Short: "Shows information about x.509 certificates and keys",
	Long: `
HTTPS Wrench certinfo: shows information about PEM encoded x.509 certificates and keys.

https-wrench certinfo can fetch certificates from a TLS endpoint, read from a PEM bundle file, and check if a 
private key matches any of the certificates.

The certificates can be verified against the system root CAs or a custom CA bundle file. 

The validation can be skipped.

If the private key is password protected, the password can be provided via the CERTINFO_PKEY_PW 
environment variable or will be prompted on stdin.

Examples:
  https-wrench certinfo --tls-endpoint example.com:443
  https-wrench certinfo --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --cert-bundle ./bundle.pem
  https-wrench certinfo --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --tls-servername www.example.com
  https-wrench certinfo --tls-endpoint [2001:db8::1]:443 --tls-insecure
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --tls-endpoint example.com:443
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --cert-bundle ./bundle.pem --key-file ./key.pem	
`,
	Run: func(cmd *cobra.Command, args []string) {
		caBundleValue := viper.GetString("ca-bundle")
		certBundleValue := viper.GetString("cert-bundle")
		keyFileValue := viper.GetString("key-file")
		versionRequested := viper.GetBool("version")

		if versionRequested {
			fmt.Print(version)
			return
		}

		// display the help if none of the main flags is set
		if len(caBundleValue+certBundleValue+keyFileValue+tlsEndpoint) == 0 {
			_ = cmd.Help()
			return
		}

		certinfoCfg, err := certinfo.NewCertinfoConfig()
		if err != nil {
			fmt.Printf("Error creating new Certinfo config: %s", err)
			return
		}

		if err = certinfoCfg.SetCaPoolFromFile(caBundleValue, fileReader); err != nil {
			fmt.Printf("Error importing CA Certificate bundle from file: %s", err)
		}

		if err = certinfoCfg.SetCertsFromFile(certBundleValue, fileReader); err != nil {
			fmt.Printf("Error importing Certificate bundle from file: %s", err)
		}

		certinfoCfg.SetTLSInsecure(tlsInsecure).SetTLSServerName(tlsServerName)

		// SetTLSEndpoint may need the SNI/ServerName and insecure options to be set
		// before being able to ask details about the certificate we want to a
		// webserver using self-signed and valid certificates
		if err = certinfoCfg.SetTLSEndpoint(tlsEndpoint); err != nil {
			fmt.Printf("Error setting TLS endpoint: %s", err)
		}

		if err = certinfoCfg.SetPrivateKeyFromFile(
			keyFileValue,
			keyPwEnvVar,
			fileReader,
		); err != nil {
			fmt.Printf("Error importing key from file: %s", err)
		}

		// dump.Print(certinfoCfg)
		if err = certinfoCfg.PrintData(os.Stdout); err != nil {
			fmt.Printf("error printing Certinfo data: %s", err)
		}
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
