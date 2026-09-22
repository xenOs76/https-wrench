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
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/view"
	"golang.org/x/term"
)

var (
	tlsEndpoint   string
	tlsServerName string
	tlsInsecure   bool
	tlsInfo       bool
	certinfoFmt   string
	keyPwEnvVar   = "CERTINFO_PKEY_PW"
)

var certinfoCmd = &cobra.Command{
	Use:   "certinfo",
	Short: "Inspect and verify x.509 certificates and keys",
	Long: `Inspect and verify PEM encoded x.509 certificates and keys.

https-wrench certinfo can fetch certificates from a TLS endpoint, read from a PEM bundle file, and check if a 
private key matches any of the certificates.

The certificates can be verified against the system root CAs or a custom CA bundle file. 

The validation can be skipped.

If the private key is password protected, the password can be provided via the CERTINFO_PKEY_PW 
environment variable or will be prompted on stdin.

Output formats:
  text (default) — human-readable lipgloss tables on a TTY; plain when piped
  json           — machine-readable report (schemaVersion, no ANSI)

Examples:

  # Print info about local certificates and keys 
  # with optional CA and public key match validation

  https-wrench certinfo --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --cert-bundle ./bundle.pem
  https-wrench certinfo --key-file ./key.pem
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --cert-bundle ./bundle.pem --key-file ./key.pem	

  # Print info about remote certificates 
  # with optional CA and public key match validation

  https-wrench certinfo --tls-endpoint example.com:443
  https-wrench certinfo --tls-endpoint example.com:443 --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --cert-bundle ./bundle.pem --key-file ./key.pem
  https-wrench certinfo --tls-endpoint example.com:443 --tls-servername www.example.com
  https-wrench certinfo --tls-endpoint [2001:db8::1]:443 --tls-insecure
  https-wrench certinfo --ca-bundle ./ca-bundle.pem --tls-endpoint example.com:443

  # Print info about remote certificates 
  # with optional display of negotiated and supported TLS protocols and ciphers

  https-wrench certinfo --tls-endpoint example.com:443 --tls-info

  # Machine-readable JSON for agents / CI

  https-wrench certinfo --cert-bundle ./bundle.pem --format json
`,
	Run: func(cmd *cobra.Command, _ []string) {
		caBundleValue := viper.GetString("ca-bundle")
		certBundleValue := viper.GetString("cert-bundle")
		keyFileValue := viper.GetString("key-file")
		versionRequested := viper.GetBool("version")

		if versionRequested {
			cmd.Print(version)
			return
		}

		if tlsInfo && tlsEndpoint == "" {
			cmd.Print("Error: --tls-info requires --tls-endpoint\n")
			return
		}

		switch certinfoFmt {
		case "", "text", "json":
		default:
			cmd.Printf("Error: unsupported --format %q (use text or json)\n", certinfoFmt)
			return
		}

		// display the help if none of the main flags is set
		if len(caBundleValue+certBundleValue+keyFileValue+tlsEndpoint) == 0 {
			_ = cmd.Help()
			return
		}

		ctx := cmd.Context()

		certinfoCfg, err := certinfo.New()
		if err != nil {
			cmd.Printf("Error creating new Certinfo config: %s", errdisp.FormatCause(err))
			return
		}

		if err = certinfoCfg.SetCaPoolFromFile(caBundleValue, fileReader); err != nil {
			cmd.Printf("Error importing CA Certificate bundle from file: %s", errdisp.FormatCause(err))
		}

		if err = certinfoCfg.SetCertsFromFile(certBundleValue, fileReader); err != nil {
			cmd.Printf("Error importing Certificate bundle from file: %s", errdisp.FormatCause(err))
		}

		certinfoCfg.SetTLSInsecure(tlsInsecure).SetTLSServerName(tlsServerName).SetTLSInfoRequested(tlsInfo)

		// SetTLSEndpoint may need the SNI/ServerName and insecure options to be set
		// before being able to ask details about the certificate we want to a
		// webserver using self-signed and valid certificates
		if err = certinfoCfg.SetTLSEndpoint(ctx, tlsEndpoint); err != nil {
			cmd.Printf("Error setting TLS endpoint: %s", errdisp.FormatCause(err))
			return
		}

		if err = certinfoCfg.SetPrivateKeyFromFile(
			keyFileValue,
			keyPwEnvVar,
			fileReader,
		); err != nil {
			cmd.Printf("Error importing key from file: %s", errdisp.FormatCause(err))
		}

		if tlsInfo {
			if err = certinfoCfg.ProbeTLSInfo(ctx); err != nil {
				cmd.Printf("Error probing TLS info: %s", errdisp.FormatCause(err))
				return
			}
		}

		result, err := certinfoCfg.BuildResult()
		if err != nil {
			cmd.Printf("error building Certinfo result: %s", errdisp.FormatCause(err))
			return
		}

		out := cmd.OutOrStdout()

		if certinfoFmt == "json" {
			payload, encErr := certinfo.EncodeJSON(result)
			if encErr != nil {
				cmd.Printf("error encoding Certinfo JSON: %s", errdisp.FormatCause(encErr))
				return
			}

			_, _ = fmt.Fprintln(out, string(payload))

			return
		}

		opts := view.Options{}
		if f, ok := out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			opts.ForceColor = true
		}

		if err = view.Render(out, certinfo.BuildDoc(result), opts); err != nil {
			cmd.Printf("error printing Certinfo data: %s", errdisp.FormatCause(err))
		}
	},
}

// init registers flags and adds the certinfo command to rootCmd.
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
	certinfoCmd.Flags().BoolVar(&tlsInfo,
		"tls-info",
		false,
		"Show negotiated TLS info and probe supported protocols/ciphers")
	certinfoCmd.Flags().StringVar(&certinfoFmt,
		"format",
		"text",
		"Output format: text (default) or json")
	rootCmd.AddCommand(certinfoCmd)
}
