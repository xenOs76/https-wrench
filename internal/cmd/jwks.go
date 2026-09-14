package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/jwks"
	"github.com/xenos76/https-wrench/internal/view"
	"golang.org/x/term"
)

var (
	jwksPublicKeyFile string
	jwksKID           string
	jwksFmt           string
)

var jwksCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Generate a JSON Web Key Set (JWKS) from a public key",
	Long: `Generate a JSON Web Key Set (JWKS) from a public key file.

The generated JWKS contains only public key parameters and is safe
to be exposed (e.g. at a /.well-known/jwks.json endpoint).

Output formats:
  text (default) — styled console view (Banner + highlighted JSON)
  json           — machine-readable report (schemaVersion, command, keys, no ANSI)

Examples:
  # Generate a public JWKS from an RSA public key
  https-wrench jwks --public-key-file rsa-public.pem

  # Generate a public JWKS with a custom Key ID (kid)
  https-wrench jwks --public-key-file ec-public.pem --kid "my-custom-key-id"

  # Emit machine-readable JSON (agents / MCP)
  https-wrench jwks --public-key-file rsa-public.pem --format json
`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		switch jwksFmt {
		case "", "text", "json":
		default:
			return fmt.Errorf("unsupported --format %q (use text or json)", jwksFmt)
		}

		result, err := jwks.Generate(cmd.Context(), jwksPublicKeyFile, jwksKID)
		if err != nil {
			cmd.PrintErrf("Error generating JWKS: %s\n", errdisp.FormatCause(err))

			return nil
		}

		out := cmd.OutOrStdout()

		if jwksFmt == "json" {
			payload, encErr := jwks.EncodeJSON(result)
			if encErr != nil {
				cmd.Printf("error encoding JWKS JSON: %s\n", errdisp.FormatCause(encErr))

				return nil
			}

			_, _ = fmt.Fprintln(out, string(payload))

			return nil
		}

		opts := view.Options{}
		if f, ok := out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			opts.ForceColor = true
		}

		if err = view.Render(out, jwks.BuildDoc(result), opts); err != nil {
			cmd.Printf("error rendering JWKS: %s\n", errdisp.FormatCause(err))

			return nil
		}

		return nil
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

	jwksCmd.Flags().StringVar(
		&jwksFmt,
		"format",
		"text",
		"Output format: text (default) or json",
	)
}
