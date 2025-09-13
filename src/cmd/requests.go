/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/
package cmd

import (
	"log"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

var (
	httpUserAgent                string = "https-wrench-request"
	httpClientDefaultMethod             = "GET"
	httpClientDefaultRequestBody []byte
	httpClientTimeout            time.Duration = 30
	httpClientKeepalive          time.Duration = 30

	transportMaxIdleConns          int           = 100
	transportIdleConnTimeout       time.Duration = 30
	transportTLSHandshakeTimeout   time.Duration = 30
	transportResponseHeaderTimeout time.Duration = 30
	transportExpectContinueTimeout time.Duration = 1

	proxyProtoDefaultSrcIPv4 string = "192.0.2.1"
	proxyProtoDefaultSrcIPv6 string = "2001:db8::1"
	proxyProtoDefaultSrcPort int    = 54321
)

var requestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Make HTTPS requests",
	Long:  `Make HTTPS requests defined in the YAML configuration file.`,

	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := LoadConfig()
		if err != nil {
			log.Fatal(err)
		}

		if cfg.Debug {
			dump.Print(cfg)
		}

		if caBundlePath != "" {
			caCerts, err := getRootCertsFromFile(caBundlePath)
			if err != nil {
				log.Fatal(err)
			}
			rootCAs = caCerts
		}

		responseMap, err := handleRequests(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if cfg.Debug {
			dump.Print(responseMap)
		}
	},
}

func init() {
	rootCmd.AddCommand(requestsCmd)
}
