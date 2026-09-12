package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/jwks"
	"github.com/xenos76/https-wrench/internal/style"
)

var (
	jwksPublicKeyFile string
	jwksKID           string
)

var jwksCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Generate a JSON Web Key Set (JWKS) from a public key",
	Long: `Generate a pretty-printed JSON Web Key Set (JWKS) from a public key file.

The generated JWKS contains only public key parameters and is safe
to be exposed (e.g. at a /.well-known/jwks.json endpoint).

Examples:
  # Generate a public JWKS from an RSA public key
  https-wrench jwks --public-key-file rsa-public.pem

  # Generate a public JWKS with a custom Key ID (kid)
  https-wrench jwks --public-key-file ec-public.pem --kid "my-custom-key-id"
`,
	Run: func(cmd *cobra.Command, _ []string) {
		jwksJSON, err := jwks.GenerateJWKS(cmd.Context(), jwksPublicKeyFile, jwksKID)
		if err != nil {
			cmd.PrintErrf("Error generating JWKS: %s\n", errdisp.FormatCause(err))

			return
		}

		// Print a nice title and then the formatted JSON
		w := cmd.OutOrStdout()
		fmt.Fprintln(w)
		fmt.Fprintln(w, style.LgSprintf(style.Cmd, "Jwks"))
		fmt.Fprintln(w)

		fmt.Fprint(w, style.CodeSyntaxHighlight("json", jwksJSON))
		fmt.Fprintln(w)
	},
}

func init() {
	rootCmd.AddCommand(jwksCmd)

	jwksCmd.Flags().StringVar(
		&jwksPublicKeyFile,
		"public-key-file",
		"",
		"File containing the PEM-encoded public key",
	)
	_ = jwksCmd.MarkFlagRequired("public-key-file")

	jwksCmd.Flags().StringVar(
		&jwksKID,
		"kid",
		"",
		"Optional explicit Key ID (kid) to use. If not provided, a SHA-256-derived ID is generated.",
	)
}
