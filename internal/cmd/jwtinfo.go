/*
Copyright © 2026 Zeno Belli <xeno@os76.xyz>
*/

package cmd

import (
	"io"
	"net/http"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
)

var (
	flagNameRequestJSONValues = "request-values-json"
	flagNameRequestValuesFile = "request-values-file"
	flagNameRequestURL        = "request-url"
	flagNameTokenFile         = "token-file"
	flagNameJwksURL           = "validation-url"
	requestJSONValues         string
	requestValuesFile         string
	requestURL                string
	tokenFile                 string
	jwksURL                   string
	keyfuncDefOverride        keyfunc.Override
)

var jwtinfoCmd = &cobra.Command{
	Use:   "jwtinfo",
	Short: "Inspect and validate JSON Web Tokens (JWT)",
	Long: `Inspect and validate JSON Web Tokens (JWT) from files or remote providers.

Examples:
  export REQ_URL="https://sample.provider/oauth/token"
  export REQ_VALUES="{\"login\":\"values\"}"
  export VALIDATION_URL="https://url.to/jwks.json"

  # Read a JWT token from a local file
  https-wrench jwtinfo --token-file /var/run/secrets/kubernetes.io/serviceaccount/token

  # Request a JWT token using inline values
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES

  # Request a JWT token using values file
  https-wrench jwtinfo --request-url $REQ_URL --request-values-file request-values.json

  # Request and validate a JWT token 
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES --validation-url $VALIDATION_URL
`,
	Run: func(cmd *cobra.Command, _ []string) {
		var (
			err       error
			tokenData jwtinfo.JwtTokenData
		)

		// TODO: remove global --config option
		if tokenFile != "" {
			tokenData, err = jwtinfo.ReadTokenFromFile(tokenFile)
			if err != nil {
				cmd.Printf(
					"error while reading token value from file: %s",
					err,
				)

				return
			}
		}

		if requestURL != "" {
			client := &http.Client{}
			requestValuesMap := make(map[string]string)

			if requestValuesFile != "" {
				requestValuesMap, err = jwtinfo.ReadRequestValuesFile(
					requestValuesFile,
					requestValuesMap,
				)
				if err != nil {
					cmd.Printf(
						"error while reading request's values from file: %s",
						err,
					)

					return
				}
			}

			if requestJSONValues != "" {
				requestValuesMap, err = jwtinfo.ParseRequestJSONValues(
					requestJSONValues,
					requestValuesMap,
				)
				if err != nil {
					cmd.Printf(
						"error while parsing request's values JSON string: %s",
						err,
					)

					return
				}
			}

			tokenData, err = jwtinfo.RequestToken(
				cmd.Context(),
				requestURL,
				requestValuesMap,
				client,
				io.ReadAll,
			)
			if err != nil {
				cmd.Printf("error while requesting token data: %s\n", err)
				return
			}
		}

		if tokenData.AccessTokenRaw != "" {
			err = tokenData.DecodeBase64()
			if err != nil {
				cmd.Printf("DecodeBase64 error: %s\n", err)
				return
			}

			if jwksURL != "" {
				err = tokenData.ParseWithJWKS(cmd.Context(), jwksURL, keyfuncDefOverride)
				if err != nil {
					cmd.Printf("error while parsing token data: %s\n", err)
					return
				}
			}

			err = jwtinfo.PrintTokenInfo(tokenData, cmd.OutOrStdout())
			if err != nil {
				cmd.Printf("error while printing token data: %s\n", err)
				return
			}
		} else {
			_ = cmd.Help()
		}
	},
}

func init() {
	rootCmd.AddCommand(jwtinfoCmd)

	jwtinfoCmd.Flags().StringVar(
		&tokenFile,
		flagNameTokenFile,
		"",
		"File containing the JWT token",
	)

	jwtinfoCmd.Flags().StringVar(
		&requestURL,
		flagNameRequestURL,
		"",
		"HTTP address to use for the JWT token request",
	)

	jwtinfoCmd.Flags().StringVar(
		&requestJSONValues,
		flagNameRequestJSONValues,
		"",
		"JSON encoded values to use for the JWT token request",
	)

	jwtinfoCmd.Flags().StringVar(
		&requestValuesFile,
		flagNameRequestValuesFile,
		"",
		"File containing the JSON encoded values to use for the JWT token request",
	)

	jwtinfoCmd.Flags().StringVar(
		&jwksURL,
		flagNameJwksURL,
		"",
		"Url of the JSON Web Key Set (JWKS) to use for validating the JWT token",
	)

	// Either read a token from a file or request it from an HTTP address
	jwtinfoCmd.MarkFlagsMutuallyExclusive(flagNameTokenFile, flagNameRequestURL)
	jwtinfoCmd.MarkFlagsOneRequired(flagNameTokenFile, flagNameRequestURL)
}
