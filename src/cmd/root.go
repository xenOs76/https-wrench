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
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"

	_ "github.com/breml/rootcerts"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile          string
	version          string = "development"
	showSampleConfig bool

	//go:embed  embedded/config-example.yaml
	sampleYamlConfig string
	caBundlePath     string
	rootCAs          *x509.CertPool
)

var rootCmd = &cobra.Command{
	Use:   "https-wrench",
	Short: "A tool to make HTTPS requests based on a YAML configuration file",
	Long:  "A tool to make HTTPS requests based on a YAML configuration file",

	Run: func(cmd *cobra.Command, args []string) {
		showVersion, _ := cmd.Flags().GetBool("version")
		if showVersion {
			fmt.Println(version)
			return
		}
		if showSampleConfig {
			fmt.Print(sampleYamlConfig)
			return
		}

		_, err := os.Stat(viper.ConfigFileUsed())
		if err != nil {
			fmt.Printf("Config file not found: %s\n", viper.ConfigFileUsed())
		}

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.https-wrench.yaml)")
	rootCmd.PersistentFlags().BoolVar(&showSampleConfig, "show-sample-config", false, "Show a sample YAML configuration")

	rootCmd.PersistentFlags().Bool("version", false, "Display the version")
	err := viper.BindPFlag("version", rootCmd.PersistentFlags().Lookup("version"))
	if err != nil {
		fmt.Printf("Error binding version flag: %v\n", err)
	}

	addCaBundleFlag(requestsCmd)
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

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func LoadConfig() (*Config, error) {
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into config struct: %s", err)
	}
	return &config, nil
}

func addCaBundleFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&caBundlePath, "ca-bundle", "", "Path to PEM CA bundle file")
	err := viper.BindPFlag("ca-bundle", cmd.Flags().Lookup("ca-bundle"))
	if err != nil {
		fmt.Printf("Error binding ca-bundle flag: %v\n", err)
	}
}
