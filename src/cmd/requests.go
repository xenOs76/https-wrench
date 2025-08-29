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

var httpUserAgent string = "https-wrench-request"
var httpClientDefaultMethod = "GET"
var httpClientDefaultRequestBody []byte
var httpClientTimeout time.Duration = 30
var httpClientKeepalive time.Duration = 30

var transportMaxIdleConns int = 100
var transportIdleConnTimeout time.Duration = 30
var transportTLSHandshakeTimeout time.Duration = 30
var transportResponseHeaderTimeout time.Duration = 30
var transportExpectContinueTimeout time.Duration = 1

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

		_, err = handleRequests(cfg)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(requestsCmd)
}
