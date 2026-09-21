package cmd

import (
	"errors"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Validate .sbx/policy.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, err := resolveProject()
		if err != nil {
			if errors.Is(err, config.ErrPolicyNotFound) {
				return exitf("Error: %v\n\nRun 'sbx-policy init' to create one.\n", err)
			}
			return exitf("Error: %v\n", err)
		}

		if ctx.policy.Sandbox == "" {
			return exitf("Error: no sandbox set in %s\n\nRun 'sbx-policy sandbox set <name>' to set one.\n", config.PolicyFileName)
		}

		ui.Success("%s is valid (sandbox: %s)", config.PolicyFileName, ctx.policy.Sandbox)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
