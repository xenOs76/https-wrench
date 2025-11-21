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
)

var (
	cfgFile        string
	version        = "development"
	caBundlePath   string
	certBundlePath string
	keyFilePath    string
)

var rootCmd = &cobra.Command{
	Use:   "https-wrench",
	Short: "HTTPS Wrench, a tool to make HTTPS requests based on a YAML configuration file",
	Long: `
HTTPS Wrench is mainly a tool to make HTTPS requests based on a YAML configuration file.

https-wrench has two subcommands: requests and certinfo.

requests is the subcommand that does HTTPS requests according to the configuration provided 
by the --config flag.

certinfo is a subcommand that reads information from PEM certificates and keys. The certificates 
can be read from local files or TLS enabled endpoints.

certinfo can compare public keys extracted from certificates and private keys to check if they match.

HTTPS Wrench is distributed with an open source license and available at the following address:
https://github.com/xenOs76/https-wrench`,

	Run: func(cmd *cobra.Command, args []string) {
		showVersion, _ := cmd.Flags().GetBool("version")
		if showVersion {
			fmt.Println(version)

			return
		}

		if cfgFile == "" {
			_ = cmd.Help()
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		return
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", "", "config file (default is $HOME/.https-wrench.yaml)")
	rootCmd.PersistentFlags().Bool("version", false, "Display the version")

	err := viper.BindPFlag("version", rootCmd.PersistentFlags().Lookup("version"))
	if err != nil {
		fmt.Printf("Error binding version flag: %v\n", err)
	}

	addCaBundleFlag(requestsCmd)
	// addCertBundleFlag(requestsCmd)
	// addKeyFileFlag(requestsCmd)

	addCaBundleFlag(certinfoCmd)
	addCertBundleFlag(certinfoCmd)
	addKeyFileFlag(certinfoCmd)
}

func initConfig() {
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

func LoadConfig() (*HTTPSWrenchConfig, error) {
	config := NewHTTPSWrenchConfig()

	err := viper.Unmarshal(config)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into config struct: %w", err)
	}

	return config, nil
}

func addCaBundleFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&caBundlePath, "ca-bundle", "", `Path to bundle file with CA certificates 
to use for validation`)

	err := viper.BindPFlag("ca-bundle", cmd.Flags().Lookup("ca-bundle"))
	if err != nil {
		fmt.Printf("Error binding ca-bundle flag: %v\n", err)
	}
}

func addCertBundleFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&certBundlePath, "cert-bundle", "", "Path to PEM Certificate bundle file")

	err := viper.BindPFlag("cert-bundle", cmd.Flags().Lookup("cert-bundle"))
	if err != nil {
		fmt.Printf("Error binding cert-bundle flag: %v\n", err)
	}
}

func addKeyFileFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&keyFilePath, "key-file", "", "Path to PEM Key file")

	err := viper.BindPFlag("key-file", cmd.Flags().Lookup("key-file"))
	if err != nil {
		fmt.Printf("Error binding key-file flag: %v\n", err)
	}
}
