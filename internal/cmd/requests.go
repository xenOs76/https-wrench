/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	"context"
	_ "embed"
	"fmt"
	"os"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/requests"
)

var (
	//go:embed  embedded/config-example.yaml
	sampleYamlConfig string
	showSampleConfig bool
)

var requestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Execute YAML-defined HTTPS requests",
	Long: `
https-wrench requests is the subcommand that does HTTPS requests according to the configuration 
pointed by the --config flag.

A sample configuration can be generated as a starting point (--show-sample-config).

The Github repository has more configuration examples: 
https://github.com/xenOs76/https-wrench/tree/main/assets/examples

It also provides a JSON schema that can be used to validate new configuration files: 
https://github.com/xenOs76/https-wrench/blob/main/https-wrench.schema.json

Examples:
 https-wrench requests --show-sample-config > https-wrench-sample-config.yaml
 https-wrench requests --config https-wrench-sample-config.yaml
	`,

	Run: func(cmd *cobra.Command, _ []string) {
		versionRequested := viper.GetBool("version")

		if versionRequested {
			cmd.Print(version)
			return
		}

		if showSampleConfig {
			fmt.Fprint(cmd.OutOrStdout(), sampleYamlConfig)
			return
		}

		if cfgFile == "" {
			_ = cmd.Help()
			return
		}

		_, err := os.Stat(viper.ConfigFileUsed())
		if err != nil {
			cmd.Printf("\nConfig file not found: %s\n", viper.ConfigFileUsed())
			_ = cmd.Help()

			return
		}

		cfg, err := LoadConfig()
		if err != nil {
			cmd.Print(err)
			return
		}

		if cfg.Debug {
			dump.Print(cfg)
		}

		requestsCfg, err := requests.NewRequestsMetaConfig()
		if err != nil {
			cmd.Print(err)
			return
		}

		requestsCfg.SetVerbose(cfg.Verbose).
			SetDebug(cfg.Debug).
			SetRequests(cfg.Requests)

		if err := requestsCfg.SetCaPoolFromYAML(cfg.CaBundle); err != nil {
			cmd.Print(errdisp.Format(err))
		}

		if err := requestsCfg.SetCaPoolFromFile(caBundlePath, fileReader); err != nil {
			cmd.Print(errdisp.Format(err))
		}

		responseMap, err := requests.HandleRequests(context.Background(), cmd.OutOrStdout(), requestsCfg)
		if err != nil {
			cmd.Print(errdisp.Format(err))
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
