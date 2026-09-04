/*
Copyright © 2025 Zeno Belli xeno@os76.xyz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"fmt"
	"os"

	// Package rootcerts provides an embedded copy of the Mozilla Included CA Certificate List,
	// more specifically the PEM of Root Certificates in Mozilla's Root Store with the Websites
	// (TLS/SSL) Trust Bit Enabled.
	// If this package is imported anywhere in the program and the crypto/x509 package cannot find
	// the system certificate pool, it will use this embedded information.
	// This is particularly useful when building Docker images "FROM scratch".
	_ "github.com/breml/rootcerts"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xenos76/https-wrench/internal/certinfo"
)

var (
	cfgFile        string
	version        = "development"
	caBundlePath   string
	certBundlePath string
	keyFilePath    string
	fileReader     certinfo.InputReader
)

var rootCmd = &cobra.Command{
	Use:   "https-wrench",
	Short: "HTTPS Wrench, a tool for maintainers of secure HTTP endpoints",
	Long: `
HTTPS Wrench is a tool for maintainers of secure HTTP endpoints. 
It enables executing YAML-defined HTTPS requests and performing in-depth 
inspection of x.509 certificates, private keys, and JSON Web Tokens.

https-wrench provides several specialized subcommands:

requests: Execute HTTPS requests according to a structured YAML configuration, 
supporting custom CA bundles and verbose output.

certinfo: Inspect PEM-encoded certificates and keys from local files or remote 
TLS endpoints. Verify certificate chains and key pairings.

jwtinfo: Decode, inspect, and validate JSON Web Tokens (JWT) using local files 
or remote JWKS endpoints.

jwks: Generate pretty-printed JSON Web Key Sets (JWKS) from public keys for 
exposure on well-known endpoints.

mcp: Run a Model Context Protocol server on stdin/stdout for AI agent integration.

Distributed under an open-source license: https://github.com/xenOs76/https-wrench`,

	Run: func(cmd *cobra.Command, _ []string) {
		showVersion, _ := cmd.Flags().GetBool("version")
		if showVersion {
			cmd.Println(version)

			return
		}

		if cfgFile == "" {
			_ = cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return err
	}

	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", "", "config file (default is $HOME/.https-wrench.yaml)")
	rootCmd.PersistentFlags().Bool("version", false, "Display the version")

	addCaBundleFlag(requestsCmd)
	// addCertBundleFlag(requestsCmd)
	// addKeyFileFlag(requestsCmd)

	addCaBundleFlag(certinfoCmd)
	addCertBundleFlag(certinfoCmd)
	addKeyFileFlag(certinfoCmd)

	bindViperFlags()
}

func bindViperFlags() {
	if err := viper.BindPFlag("version", rootCmd.PersistentFlags().Lookup("version")); err != nil {
		fmt.Printf("Error binding version flag: %v\n", err)
	}

	if err := viper.BindPFlag("ca-bundle", requestsCmd.Flags().Lookup("ca-bundle")); err != nil {
		fmt.Printf("Error binding ca-bundle flag: %v\n", err)
	}

	if err := viper.BindPFlag("ca-bundle", certinfoCmd.Flags().Lookup("ca-bundle")); err != nil {
		fmt.Printf("Error binding ca-bundle flag: %v\n", err)
	}

	if err := viper.BindPFlag("cert-bundle", certinfoCmd.Flags().Lookup("cert-bundle")); err != nil {
		fmt.Printf("Error binding cert-bundle flag: %v\n", err)
	}

	if err := viper.BindPFlag("key-file", certinfoCmd.Flags().Lookup("key-file")); err != nil {
		fmt.Printf("Error binding key-file flag: %v\n", err)
	}
}

func initConfig() {
	if isMCPCommand() {
		return
	}

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".https-wrench")
	}

	// viper.AutomaticEnv() // read in environment variables that match

	err := viper.ReadInConfig()
	if err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// LoadConfig reads the configuration file and unmarshals it into an HTTPSWrenchConfig struct.
func LoadConfig() (*HTTPSWrenchConfig, error) {
	config := NewHTTPSWrenchConfig()

	err := viper.Unmarshal(config)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into config struct: %w", err)
	}

	return config, nil
}

func isMCPCommand() bool {
	for _, arg := range os.Args[1:] {
		if arg == "mcp" {
			return true
		}
	}

	return false
}

func addCaBundleFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&caBundlePath, "ca-bundle", "", `Path to bundle file with CA certificates 
to use for validation`)
}

func addCertBundleFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&certBundlePath, "cert-bundle", "", "Path to PEM Certificate bundle file")
}

func addKeyFileFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&keyFilePath, "key-file", "", "Path to PEM Key file")
}
