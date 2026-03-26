/*
Copyright © 2026 Zeno Belli <xeno@os76.xyz>
*/

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
)

var (
	flagNameRequestJSONValues = "request-values-json"
	flagNameRequestValuesFile = "request-values-file"
	flagNameRequestURL        = "request-url"
	flagNameJwksURL           = "validation-url"
	requestJSONValues         string
	requestValuesFile         string
	requestURL                string
	jwksURL                   string
	keyfuncDefOverride        keyfunc.Override
)

var jwtinfoCmd = &cobra.Command{
	Use:   "jwtinfo",
	Short: "JwtInfo request and display JWT token data",
	Long: `JwtInfo request and display JWT token data

Examples:
  export REQ_URL="https://sample.provider/oauth/token"
  export REQ_VALUES="{\"login\":\"values\"}"
  export VALIDATION_URL="https://url.to/jkws.json"

  # Get the JWT token using inline values
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES

  # Get the JWT token using values file
  https-wrench jwtinfo --request-url $REQ_URL --request-values-file request-values.json

  # Get and validate the JWT token 
  https-wrench jwtinfo --request-url $REQ_URL --request-values-json $REQ_VALUES --validation-url $VALIDATION_URL
`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: display version and exit
		// TODO: remove global --config option

		if len(requestJSONValues+requestURL) == 0 && len(requestValuesFile+requestURL) == 0 {
			_ = cmd.Help()
			return
		}

		var err error
		client := &http.Client{}
		requestValuesMap := make(map[string]string)

		if requestValuesFile != "" {
			requestValuesMap, err = jwtinfo.ReadRequestValuesFile(
				requestValuesFile,
				requestValuesMap,
			)
			if err != nil {
				fmt.Printf(
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
				fmt.Printf(
					"error while parsing request's values JSON string: %s",
					err,
				)
				return
			}
		}

		tokenData, err := jwtinfo.RequestToken(
			requestURL,
			requestValuesMap,
			client,
			io.ReadAll,
		)
		if err != nil {
			fmt.Printf("error while requesting token data: %s\n", err)
			return
		}

		err = tokenData.DecodeBase64()
		if err != nil {
			fmt.Printf("DecodeBase64 error: %s\n", err)
			return
		}

		if jwksURL != "" {
			err = tokenData.ParseWithJWKS(jwksURL, keyfuncDefOverride)
			if err != nil {
				fmt.Printf("error while parsing token data: %s\n", err)
				return
			}
		}

		err = jwtinfo.PrintTokenInfo(tokenData, os.Stdout)
		if err != nil {
			fmt.Printf("error while printing token data: %s\n", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(jwtinfoCmd)

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

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// jwtinfoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
