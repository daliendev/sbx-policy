package cmd

import (
	"errors"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var allowCmd = &cobra.Command{
	Use:   "allow <host> [host...]",
	Short: "Add hosts to the network allowlist in .sbx/policy.yaml",
	Long: `Add hosts to the network allowlist in .sbx/policy.yaml.

Hosts may be given as separate arguments, comma-separated within a single
argument, or a mix of both:

  sbx-policy allow github.com registry.npmjs.org
  sbx-policy allow github.com,registry.npmjs.org`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hosts := splitCommaSeparated(args)
		if len(hosts) == 0 {
			return exitf("Error: no host found in arguments\n")
		}
		for _, entry := range hosts {
			if err := policy.ValidateNetworkEntry(entry); err != nil {
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

		updated, added := addUnique(ctx.policy.NetworkAllowlist, hosts)
		if len(added) == 0 {
			ui.Success("All hosts already present in %s", config.PolicyFileName)
			return nil
		}

		ctx.policy.NetworkAllowlist = updated
		if err := config.Write(ctx.root, ctx.policy); err != nil {
			return err
		}
		ui.Success("Added host(s):")
		ui.PrintList(added, "•")
		return offerSync()
	},
}

func init() {
	rootCmd.AddCommand(allowCmd)
}
