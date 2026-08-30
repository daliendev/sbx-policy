package cmd

import (
	"os"

	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbx-policy",
	Short: "Project-level network allowlist manager for Docker Sandbox",
	Long: `sbx-policy provides a declarative, project-scoped network allowlist
that synchronizes with Docker Sandbox (sbx). It warns you when the policy
has changed since you last approved it.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		ui.Error("%v", err)
		os.Exit(1)
	}
}
