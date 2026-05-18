/*
Copyright © 2026 Zeno Belli <xeno@os76.xyz>
*/

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/jwtinfo"
	"github.com/xenos76/https-wrench/internal/style"
)

var (
	flagNameRequestValues     = "request-values"
	flagNameRequestJSONValues = "request-values-json"
	flagNameRequestValuesFile = "request-values-file"
	flagNameRequestURL        = "request-url"
	flagNameTokenFile         = "token-file"
	flagNameJwksURL           = "validation-url"
	flagNameRefresh           = "refresh"
	flagNameTokenOutputFile   = "token-output-file"
	flagNameRenewThreshold    = "renew-threshold"
	requestURL                string
	tokenFile                 string
	jwksURL                   string
	refresh                   bool
	tokenOutputFile           string
	renewThreshold            float64
	keyfuncDefOverride        keyfunc.Override

	// requestSteps tracks the sequence of request-related flags as they appear on the command line.
	requestSteps []requestValueStep
)

// requestValueStep represents a single occurrence of a request flag and its value.
type requestValueStep struct {
	kind  string // "json", "file", or "kv"
	value string
}

// stepFlag implements the pflag.Value interface to capture the order of flag occurrences.
type stepFlag struct {
	kind string
}

func (*stepFlag) String() string { return "" }

// Set appends the flag's value and its type to the global requestSteps slice.
func (f *stepFlag) Set(s string) error {
	requestSteps = append(requestSteps, requestValueStep{kind: f.kind, value: s})
	return nil
}

func (*stepFlag) Type() string { return "string" }

var jwtinfoCmd = &cobra.Command{
	Use:   "jwtinfo",
	Short: "Inspect and validate JSON Web Tokens (JWT)",
	Long: `Inspect and validate JSON Web Tokens (JWT) from files or remote providers.

Examples:
  export REQ_URL="https://sample.provider/oauth/token"
  export REQ_VALUES="{\"login\":\"values\"}"
  export VALIDATION_URL="https://oidc.sample.url/oidc-sample-id/.well-known/jwks.json"

  # Read a JWT token from a local file
  https-wrench jwtinfo --token-file /var/run/secrets/kubernetes.io/serviceaccount/token

  # Request a JWT token using inline values
  https-wrench jwtinfo \
   --request-url $REQ_URL \
   --request-values-json $REQ_VALUES

  # Request a JWT token using values file
  https-wrench jwtinfo \
   --request-url $REQ_URL \
   --request-values-file request-values.json

  # Request a JWT token using request-values flag
  https-wrench jwtinfo \
   --request-url $REQ_URL \
   --request-values username=test \
   --request-values password=test \
   --request-values scope=login

  # Request and validate a JWT token 
  https-wrench jwtinfo \
   --request-url $REQ_URL \
   --request-values-json $REQ_VALUES \
   --validation-url $VALIDATION_URL

  # Request a JWT token, write it to a file and refresh it before expiration
  https-wrench jwtinfo \
   --request-url $REQ_URL \
   --request-values-json $REQ_VALUES \
   --token-output-file /tmp/token \
   --refresh
`,
	Run: func(cmd *cobra.Command, _ []string) {
		var (
			err              error
			tokenData        *jwtinfo.JwtTokenData
			client           = &http.Client{}
			requestValuesMap = make(map[string]string)
		)

		if refresh && requestURL == "" {
			fmt.Fprintln(cmd.OutOrStdout(), style.LgSprintf(style.Error, "Error: --refresh requires --request-url"))
			return
		}

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
			for _, step := range requestSteps {
				switch step.kind {
				case "json":
					requestValuesMap, err = jwtinfo.ParseRequestJSONValues(
						step.value,
						requestValuesMap,
					)
				case "file":
					requestValuesMap, err = jwtinfo.ReadRequestValuesFile(
						step.value,
						requestValuesMap,
					)
				case "kv":
					requestValuesMap, err = jwtinfo.ParseKVValue(
						step.value,
						requestValuesMap,
					)
				default:
					continue
				}

				if err != nil {
					cmd.Printf("error processing %s: %s\n", step.kind, err)
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

		if tokenData != nil && tokenData.AccessTokenRaw != "" {
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

			if tokenOutputFile != "" {
				tokenData.WriteTokenToFile(tokenOutputFile, cmd.OutOrStdout())
			}

			if refresh {
				// Setup graceful shutdown
				ctx, cancel := context.WithCancel(cmd.Context())
				defer cancel()

				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

				go func() {
					<-sigCh
					cancel()
				}()

				cmd.Printf("Starting refresh loop...\n")

				err := tokenData.RefreshLoop(
					ctx,
					requestURL,
					requestValuesMap,
					client,
					io.ReadAll,
					renewThreshold,
					tokenOutputFile,
					cmd.OutOrStdout(),
				)
				if err != nil {
					cmd.Printf("Refresh loop exited with error: %s\n", err)
				} else {
					cmd.Printf("Refresh loop stopped gracefully.\n")
				}
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

	jwtinfoCmd.Flags().Var(
		&stepFlag{kind: "json"},
		flagNameRequestJSONValues,
		"JSON encoded values to use for the JWT token request",
	)

	jwtinfoCmd.Flags().Var(
		&stepFlag{kind: "file"},
		flagNameRequestValuesFile,
		"File containing the JSON encoded values to use for the JWT token request",
	)

	jwtinfoCmd.Flags().Var(
		&stepFlag{kind: "kv"},
		flagNameRequestValues,
		"Key-value pairs to use for the JWT token request (e.g., key=value)",
	)

	jwtinfoCmd.Flags().StringVar(
		&jwksURL,
		flagNameJwksURL,
		"",
		"Url of the JSON Web Key Set (JWKS) to use for validating the JWT token",
	)

	jwtinfoCmd.Flags().BoolVar(
		&refresh,
		flagNameRefresh,
		false,
		"Run in foreground and automatically refresh the token",
	)

	jwtinfoCmd.Flags().StringVar(
		&tokenOutputFile,
		flagNameTokenOutputFile,
		"",
		"File to write the refreshed token to",
	)

	jwtinfoCmd.Flags().Float64Var(
		&renewThreshold,
		flagNameRenewThreshold,
		80.0,
		"Percentage of token lifetime to wait before refreshing",
	)

	// Either read a token from a file or request it from an HTTP address
	jwtinfoCmd.MarkFlagsMutuallyExclusive(flagNameTokenFile, flagNameRequestURL)
	jwtinfoCmd.MarkFlagsOneRequired(flagNameTokenFile, flagNameRequestURL)
}
