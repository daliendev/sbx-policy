package cmd

import (
	"errors"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage the target sandbox in .sbx/policy.yaml",
}

var sandboxSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Set the target sandbox name in the policy file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := policy.ValidateSandboxName(name); err != nil {
			return exitf("Error: %v\n", err)
		}

		ctx, err := resolveProject()
		if err != nil {
			if errors.Is(err, config.ErrPolicyNotFound) {
				return exitf("Error: %v\n\nRun 'sbx-policy init' to create one.\n", err)
			}
			return exitf("Error: %v\n", err)
		}

		if ctx.policy.Sandbox == name {
			ui.Success("Sandbox already set to %s", name)
			return nil
		}
		if ctx.policy.Sandbox != "" {
			ui.Warning("Sandbox changed from %s to %s", ctx.policy.Sandbox, name)
		}

		ctx.policy.Sandbox = name
		if err := config.Write(ctx.root, ctx.policy); err != nil {
			return err
		}
		ui.Success("Sandbox set to %s in %s", name, config.PolicyFileName)
		return offerSync()
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxSetCmd)
	rootCmd.AddCommand(sandboxCmd)
}
