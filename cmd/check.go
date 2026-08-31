package cmd

import (
	"errors"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/state"
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

		mgr := state.NewManager()
		stored, found, err := mgr.Load(ctx.identity.StateKey())
		if err != nil {
			ui.Warning("Could not load remembered state: %v", err)
		}

		sandbox := ctx.policy.Sandbox
		if sandbox == "" && found {
			sandbox = stored.Sandbox
		}

		if sandbox != "" {
			ui.Success(".sbx/policy.yaml is valid (sandbox: %s)", sandbox)
		} else {
			ui.Success(".sbx/policy.yaml is valid")
			ui.Warning("No sandbox configured. 'sbx-policy sync' will fail until you set one.")
			ui.Warning("Add 'sandbox: <name>' to .sbx/policy.yaml or pass --sandbox to sync.")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
