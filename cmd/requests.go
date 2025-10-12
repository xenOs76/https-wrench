/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	_ "embed"
	"fmt"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
	"github.com/xenos76/https-wrench/internal/requests"
)

var (
	//go:embed  embedded/config-example.yaml
	sampleYamlConfig string
	showSampleConfig bool
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

		requestsCfg, err := requests.NewRequestsConfig()
		if err != nil {
			fmt.Print(err)
			return
		}

		requestsCfg.SetVerbose(cfg.Verbose).
			SetDebug(cfg.Debug).
			SetRequests(cfg.Requests)

		if err := requestsCfg.SetCaPoolFromYAML(cfg.CaBundle); err != nil {
			fmt.Print(err)
		}

		if err := requestsCfg.SetCaPoolFromFile(caBundlePath); err != nil {
			fmt.Print(err)
		}

		responseMap, err := requests.HandleRequests(requestsCfg)
		if err != nil {
			fmt.Print(err)
		}

		if cfg.Debug {
			// dump.Print(cfg)
			dump.Print(requestsCfg)
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
