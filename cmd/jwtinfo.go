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
	flagNameRequestURL        = "request-url"
	flagNameJwksURL           = "validation-url"
	requestJSONValues         string
	requestURL                string
	jwksURL                   string
	keyfuncDefOverride        keyfunc.Override
)

var jwtinfoCmd = &cobra.Command{
	Use:   "jwtinfo",
	Short: "Request and display JWT token data",
	Long:  `Request and display JWT token data.`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		client := &http.Client{}
		requestValuesMap := make(map[string]string)

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
		}

		// TODO: turn into method
		token, err := jwtinfo.ParseTokenData(tokenData, jwksURL, keyfuncDefOverride)
		if err != nil {
			fmt.Printf("error while parsing token data: %s\n", err)
			return
		}

		fmt.Printf("Token valid: %v\n", token.Valid)

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
		&jwksURL,
		flagNameJwksURL,
		"",
		"Url of the JSON Web Key Set (JWKS) to use for validating the JWT token",
	)

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// jwtinfoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
