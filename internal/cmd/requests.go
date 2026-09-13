/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/requests"
	"github.com/xenos76/https-wrench/internal/view"
	"golang.org/x/term"
)

var (
	//go:embed  embedded/config-example.yaml
	sampleYamlConfig string
	showSampleConfig bool
	requestsFmt      string
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

		switch requestsFmt {
		case "", "text", "json":
		default:
			cmd.Printf("Error: unsupported --format %q (use text or json)\n", requestsFmt)
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

		if cfg.Debug && requestsFmt != "json" {
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

		debugOut := cmd.OutOrStdout()
		if requestsFmt == "json" {
			debugOut = cmd.ErrOrStderr()
		}

		result, responseMap, err := requestsCfg.ExecuteWithWriter(cmd.Context(), debugOut)
		if err != nil {
			cmd.Print(errdisp.Format(err))
			return
		}

		if cfg.Debug {
			if requestsFmt == "json" {
				dump.Fprint(cmd.ErrOrStderr(), requestsCfg)
				dump.Fprint(cmd.ErrOrStderr(), responseMap)
			} else {
				dump.Print(requestsCfg)
				dump.Print(responseMap)
			}
		}

		out := cmd.OutOrStdout()

		if requestsFmt == "json" {
			payload, encErr := requests.EncodeJSON(result)
			if encErr != nil {
				cmd.Printf("error encoding Requests JSON: %s\n", errdisp.FormatCause(encErr))
				return
			}

			_, _ = fmt.Fprintln(out, string(payload))

			return
		}

		if cfg.Verbose {
			opts := view.Options{}
			if f, ok := out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				opts.ForceColor = true
			}

			if err = view.Render(out, requests.BuildDoc(result), opts); err != nil {
				cmd.Printf("error printing Requests data: %s\n", errdisp.FormatCause(err))
			}
		}
	},
}

func init() {
	requestsCmd.PersistentFlags().BoolVar(&showSampleConfig,
		"show-sample-config",
		false,
		"Show a sample YAML configuration")
	requestsCmd.Flags().StringVar(
		&requestsFmt,
		"format",
		"text",
		"Output format: text (human-readable) or json (machine-readable, no ANSI)",
	)
	rootCmd.AddCommand(requestsCmd)
}
