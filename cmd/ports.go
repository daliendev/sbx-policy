package cmd

import (
	"errors"
	"fmt"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/reconcile"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Manage port mappings in .sbx/policy.yaml",
}

var portsAddCmd = &cobra.Command{
	Use:   "add <mapping> [mapping...]",
	Short: "Add port mappings to the policy file",
	Long: `Each mapping is either hostPort:sandboxPort (e.g. 8080:3000) or a
bare sandbox port (e.g. 3000, letting the OS pick a free host port).`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, entry := range args {
			if err := policy.ValidatePortMapping(entry); err != nil {
				return exitf("Error: %v\n", err)
			}
		}

		ctx, err := resolveProject()
		if err != nil {
			if errors.Is(err, config.ErrPolicyNotFound) {
				return exitf("Error: %v\n\nRun 'sbx-policy init' to create one.\n", err)
			}
			return exitf("Error: %v\n", err)
		}

		updated, added := addUnique(ctx.policy.Ports, args)
		if len(added) == 0 {
			ui.Success("All port mappings already present in %s", config.PolicyFileName)
			return nil
		}

		ctx.policy.Ports = updated
		if err := config.Write(ctx.root, ctx.policy); err != nil {
			return err
		}
		ui.Success("Added port mapping(s):")
		ui.PrintList(added, "•")

		err = offerSync()
		if err == nil {
			return nil
		}

		// Only roll back mappings this command added and sbx refused to
		// publish: any other failure says nothing about the new entries, and
		// the ones that were published (or never attempted) stay in the file.
		var rejected []string
		var pubErr *reconcile.PublishError
		if errors.As(err, &pubErr) {
			rejected = intersectEntries(added, []string{pubErr.Mapping})
		}
		if len(rejected) == 0 {
			return err
		}
		ctx.policy.Ports = removeEntries(ctx.policy.Ports, rejected)
		if writeErr := config.Write(ctx.root, ctx.policy); writeErr != nil {
			return errors.Join(err, fmt.Errorf("also failed to roll back %s: %w", config.PolicyFileName, writeErr))
		}
		ui.Warning("sbx rejected these port mapping(s); removed from %s:", config.PolicyFileName)
		ui.PrintList(rejected, "•")
		return err
	},
}

func init() {
	portsCmd.AddCommand(portsAddCmd)
	rootCmd.AddCommand(portsCmd)
}
