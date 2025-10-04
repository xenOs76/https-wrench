/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	"fmt"
	"time"

	_ "embed"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

const (
	httpClientTimeout   time.Duration = 30 * time.Second
	httpClientKeepalive time.Duration = 30 * time.Second

	transportMaxIdleConns          int           = 100
	transportIdleConnTimeout       time.Duration = 30 * time.Second
	transportTLSHandshakeTimeout   time.Duration = 30 * time.Second
	transportResponseHeaderTimeout time.Duration = 30 * time.Second
	transportExpectContinueTimeout time.Duration = 1 * time.Second
)

var (
	//go:embed  embedded/config-example.yaml
	sampleYamlConfig string
	showSampleConfig bool

	httpUserAgent                = "https-wrench-request"
	httpClientDefaultMethod      = "GET"
	httpClientDefaultRequestBody []byte

	proxyProtoDefaultSrcIPv4 = "192.0.2.1"
	proxyProtoDefaultSrcIPv6 = "2001:db8::1"
	proxyProtoDefaultSrcPort = 54321
)

var requestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Make HTTPS requests",
	Long:  `Make HTTPS requests defined in the YAML configuration file.`,

	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := LoadConfig()
		if err != nil {
			fmt.Print(err)
			return
		}

		if showSampleConfig {
			fmt.Print(sampleYamlConfig)
			return
		}

		if cfg.Debug {
			dump.Print(cfg)
		}

		if caBundlePath != "" {
			caCerts, cabErr := getRootCertsFromFile(caBundlePath)
			if cabErr != nil {
				fmt.Print(cabErr)
				return
			}
			rootCAs = caCerts
		}

		responseMap, err := handleRequests(cfg)
		if err != nil {
			fmt.Print(err)
			return
		}
		if cfg.Debug {
			dump.Print(responseMap)
		}
	},
}

func init() {
	requestsCmd.PersistentFlags().BoolVar(&showSampleConfig,
		"show-sample-config",
		false,
		"Show a sample YAML configuration")
	rootCmd.AddCommand(requestsCmd)
}
