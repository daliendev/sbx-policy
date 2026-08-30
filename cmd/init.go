package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new .sbx/policy.yaml in the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		root, err := config.FindProjectRoot(wd)
		if err == nil {
			ui.Success("%s already exists at %s", config.PolicyFileName, root)
			return nil
		}
		if !errors.Is(err, config.ErrPolicyNotFound) {
			return fmt.Errorf("search for existing policy: %w", err)
		}

		p := config.DefaultPolicy()
		if err := config.Write(wd, p); err != nil {
			return err
		}

		ui.Success("Created %s", config.PolicyFileName)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
