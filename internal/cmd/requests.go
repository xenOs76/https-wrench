/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/errdisp"
	"github.com/xenos76/https-wrench/internal/observability"
	"github.com/xenos76/https-wrench/internal/requests"
	"github.com/xenos76/https-wrench/internal/view"
	"golang.org/x/term"
)

var (
	//go:embed  embedded/config-example.yaml
	sampleYamlConfig      string
	showSampleConfig      bool
	requestsFmt           string
	requestsConcurrency   int
	observeMode           bool
	observeInterval       time.Duration
	observeListen         string
	observeRemoteWriteURL string
	observeOTLPEndpoint   string
	observeLogLevel       string
	observeLogFormat      string
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
 https-wrench requests --config https-wrench-sample-config.yaml --format json
	`,

	Run: func(cmd *cobra.Command, _ []string) {
		defer func() {
			observeMode = false
			observeInterval = 0
			observeListen = ""
			observeRemoteWriteURL = ""
			observeOTLPEndpoint = ""
			observeLogLevel = ""
			observeLogFormat = ""
		}()

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

		concurrency := requestsConcurrency
		if !cmd.Flags().Changed("concurrency") && cfg.Concurrency > 0 {
			concurrency = cfg.Concurrency
		}

		requestsCfg.SetVerbose(cfg.Verbose).
			SetDebug(cfg.Debug).
			SetConcurrency(concurrency).
			SetRequests(cfg.Requests)

		if err := requestsCfg.SetCaPoolFromYAML(cfg.CaBundle); err != nil {
			cmd.Print(errdisp.Format(err))
		}

		if err := requestsCfg.SetCaPoolFromFile(caBundlePath, fileReader); err != nil {
			cmd.Print(errdisp.Format(err))
		}

		isObservability := observeMode || cfg.Observability.Enabled
		if isObservability {
			obsCfg := applyObservabilityOverrides(cfg.Observability, cmd)

			runner, err := observability.NewRunner(obsCfg, requestsCfg)
			if err != nil {
				cmd.Print(errdisp.Format(err))
				return
			}

			cfgFilePath := viper.ConfigFileUsed()
			runner.SetReloader(cfgFilePath, func() (*observability.Config, *requests.RequestsMetaConfig, error) {
				return loadAndBuildObservabilityConfigs(cfgFilePath, cmd, fileReader)
			})

			runner.SetOutput(cmd.OutOrStdout())

			runCtx := cmd.Context()
			if cmd.HasParent() && cmd.Parent().Context() != nil {
				runCtx = cmd.Parent().Context()
			}

			if err := runner.Run(runCtx); err != nil {
				cmd.Print(errdisp.Format(err))
				return
			}

			return
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

// init registers flags and adds the requests command to rootCmd.
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
	requestsCmd.Flags().IntVarP(
		&requestsConcurrency,
		"concurrency",
		"c",
		requests.DefaultRequestsConcurrency,
		"Maximum number of concurrent HTTP requests (1 for sequential)",
	)
	requestsCmd.Flags().BoolVar(
		&observeMode,
		"observe",
		false,
		"Run in continuous observability mode (executing requests by interval and exporting metrics)",
	)
	requestsCmd.Flags().DurationVar(
		&observeInterval,
		"interval",
		0,
		"Probe execution interval in observability mode (e.g. 15s, 30s, 1m; overrides config)",
	)
	requestsCmd.Flags().StringVar(
		&observeListen,
		"listen",
		"",
		"Address for the Prometheus metrics scrape server (e.g. :9090; overrides config)",
	)
	requestsCmd.Flags().StringVar(
		&observeRemoteWriteURL,
		"remote-write-url",
		"",
		"Prometheus remote_write endpoint URL to push metrics to (overrides config)",
	)
	requestsCmd.Flags().StringVar(
		&observeOTLPEndpoint,
		"otlp-endpoint",
		"",
		"OpenTelemetry OTLP endpoint URL to push metrics to (overrides config)",
	)
	requestsCmd.Flags().StringVar(
		&observeLogLevel,
		"log-level",
		"",
		"Log level in observability mode: debug, info, warn, error (overrides config)",
	)
	requestsCmd.Flags().StringVar(
		&observeLogFormat,
		"log-format",
		"",
		"Log format in observability mode: text, json (overrides config)",
	)
	rootCmd.AddCommand(requestsCmd)
}

// loadAndBuildObservabilityConfigs reads a YAML configuration file from disk and parses both the
// observability configuration and requests metadata configuration for dynamic reload cycles.
func loadAndBuildObservabilityConfigs(
	configFile string,
	cmd *cobra.Command,
	reader certinfo.Reader,
) (*observability.Config, *requests.RequestsMetaConfig, error) {
	v := viper.New()
	v.SetConfigFile(configFile)

	if err := v.ReadInConfig(); err != nil {
		return nil, nil, fmt.Errorf("unable to read config file %q: %w", configFile, err)
	}

	cfg := NewHTTPSWrenchConfig()
	if err := v.Unmarshal(cfg); err != nil {
		return nil, nil, fmt.Errorf("unable to decode config: %w", err)
	}

	reqsCfg, err := requests.NewRequestsMetaConfig()
	if err != nil {
		return nil, nil, err
	}

	concurrency := requestsConcurrency
	if !cmd.Flags().Changed("concurrency") && cfg.Concurrency > 0 {
		concurrency = cfg.Concurrency
	}

	reqsCfg.SetVerbose(cfg.Verbose).
		SetDebug(cfg.Debug).
		SetConcurrency(concurrency).
		SetRequests(cfg.Requests)

	if err := reqsCfg.SetCaPoolFromYAML(cfg.CaBundle); err != nil {
		return nil, nil, err
	}

	if err := reqsCfg.SetCaPoolFromFile(caBundlePath, reader); err != nil {
		return nil, nil, err
	}

	obsCfg := applyObservabilityOverrides(cfg.Observability, cmd)
	if err := obsCfg.Validate(); err != nil {
		return nil, nil, err
	}

	return &obsCfg, reqsCfg, nil
}

// applyObservabilityOverrides merges CLI flag overrides into the base observability configuration.
func applyObservabilityOverrides(base observability.Config, cmd *cobra.Command) observability.Config {
	obsCfg := base
	obsCfg.Enabled = true

	if cmd.Flags().Changed("interval") && observeInterval > 0 {
		obsCfg.Interval = observeInterval
	}

	if cmd.Flags().Changed("listen") && observeListen != "" {
		obsCfg.Pull.Enabled = true
		obsCfg.Pull.Address = observeListen
	}

	if cmd.Flags().Changed("remote-write-url") && observeRemoteWriteURL != "" {
		obsCfg.Push.Prometheus.Enabled = true
		obsCfg.Push.Prometheus.RemoteWriteURL = observeRemoteWriteURL
	}

	if cmd.Flags().Changed("otlp-endpoint") && observeOTLPEndpoint != "" {
		obsCfg.Push.OTLP.Enabled = true
		obsCfg.Push.OTLP.Endpoint = observeOTLPEndpoint
	}

	if cmd.Flags().Changed("log-level") && observeLogLevel != "" {
		obsCfg.Logging.Level = observeLogLevel
	}

	if cmd.Flags().Changed("log-format") && observeLogFormat != "" {
		obsCfg.Logging.Format = observeLogFormat
	}

	return obsCfg
}
