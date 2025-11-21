/*
Copyright © 2025 Zeno Belli <xeno@os76.xyz>
*/

package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var manPagesDestDir string

var manCmd = &cobra.Command{
	Use:    "man",
	Short:  "create manpages for HTTPS Wrench",
	Long:   "Create manpages for HTTPS Wrench commands",
	Hidden: true,
	Run: func(_ *cobra.Command, _ []string) {
		now := time.Now()
		rootHeader := &doc.GenManHeader{
			Title:   "HTTPS-WRENCH",
			Section: "1",
			Date:    &now,
			Source:  "https-wrench",
		}
		err := doc.GenManTree(rootCmd, rootHeader, manPagesDestDir)
		if err != nil {
			fmt.Print(err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(manCmd)
	manCmd.Flags().StringVar(&manPagesDestDir, "dest-dir",
		".", "Destination directory for the man pages files")
}
