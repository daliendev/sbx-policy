package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/sbx"
	"github.com/daliendev/sbx-policy/internal/state"
	"github.com/daliendev/sbx-policy/internal/ui"
	"github.com/spf13/cobra"
)

var sandboxFlag string
var yesFlag bool

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize network allowlist with Docker Sandbox",
	RunE:  doSync,
}

func doSync(cmd *cobra.Command, args []string) error {
	ctx, err := resolveProject()
	if err != nil {
		if errors.Is(err, config.ErrPolicyNotFound) {
			return exitf("Error: %v\n\nRun 'sbx-policy init' to create one.\n", err)
		}
		return exitf("Error: %v\n", err)
	}

	mgr := state.NewManager()
	key := ctx.identity.StateKey()
	stored, found, err := mgr.Load(key)
	if err != nil {
		ui.Warning("Could not load remembered state: %v", err)
	}

	desiredAllowlist := policy.Normalize(ctx.policy.NetworkAllowlist)
	desiredPorts := policy.Normalize(ctx.policy.Ports)
	sandbox := resolveSandbox(sandboxFlag, ctx.policy.Sandbox, stored.Sandbox, found)

	if sandbox == "" {
		ui.Error("No sandbox specified for this project.")
		ui.Separator()
		ui.Info("sbx-policy sync scopes network rules to individual sandboxes")
		ui.Info("instead of applying them globally.")
		ui.Separator()
		ui.Info("To specify a sandbox, use one of:")
		ui.Info("  1. Pass --sandbox <name> to sbx-policy sync")
		ui.Info("  2. Add 'sandbox: <name>' to .sbx/policy.yaml")
		ui.Separator()
		ui.Info("To create a sandbox first, run your tool normally:")
		ui.Info("  sbx run <tool> .")
		return fmt.Errorf("no sandbox specified")
	}

	if !yesFlag && !isStdinTerminal() {
		ui.Error("This appears to be a non-interactive environment.")
		ui.Info("Use --yes to approve the sync without prompting.")
		return fmt.Errorf("non-interactive environment")
	}

	if !confirmSync(desiredAllowlist, desiredPorts, sandbox, stored.Allowlist, stored.Ports, found) {
		ui.Info("Aborted.")
		return fmt.Errorf("aborted")
	}

	client := sbx.NewClient()
	if err := client.SyncNetworkPolicy(desiredAllowlist, sandbox); err != nil {
		return exitf("Error: %v\n", err)
	}
	if err := client.SyncPorts(desiredPorts, sandbox); err != nil {
		return exitf("Error: %v\n", err)
	}

	if err := mgr.Save(key, state.ProjectState{Allowlist: desiredAllowlist, Sandbox: sandbox, Ports: desiredPorts}); err != nil {
		ui.Warning("Could not save remembered state: %v", err)
	}

	ui.Success("Network allowlist and ports synchronized to sandbox %s", sandbox)
	return nil
}

// isStdinTerminal returns true when os.Stdin is a character device (i.e. an
// interactive terminal), as opposed to a pipe or file redirect.
func isStdinTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// resolveSandbox returns the effective sandbox name using the priority:
// CLI flag > policy file > remembered state.
func resolveSandbox(flag, policySandbox, storedSandbox string, found bool) string {
	if flag != "" {
		return flag
	}
	if policySandbox != "" {
		return policySandbox
	}
	if found {
		return storedSandbox
	}
	return ""
}

// confirmSync prompts the user when the allowlist or ports changed, or when
// there is no previous state. It returns true if the sync should proceed.
func confirmSync(desiredAllowlist, desiredPorts []string, sandbox string, storedAllowlist, storedPorts []string, found bool) bool {
	if yesFlag {
		return true
	}

	allowlistDiff := policy.Compare(policy.Normalize(storedAllowlist), desiredAllowlist)
	portsDiff := policy.Compare(policy.Normalize(storedPorts), desiredPorts)
	noChanges := !allowlistDiff.HasChanges() && !portsDiff.HasChanges()

	if !found {
		ui.Info("No previous network policy found for this project.")
		ui.Separator()
		ui.Info("Sandbox: %s", sandbox)
		ui.Info("Network allowlist:")
		ui.PrintList(desiredAllowlist, "•")
		if len(desiredPorts) > 0 {
			ui.Info("Ports:")
			ui.PrintList(desiredPorts, "•")
		}
		ui.Separator()
		return ask("Initialize and continue? [Y/n] ", true)
	}

	if noChanges {
		ui.Success("Network allowlist and ports unchanged for sandbox %s", sandbox)
		return true
	}

	ui.Warning("Policy changed since last approval")
	ui.Separator()
	ui.Info("Sandbox: %s", sandbox)
	ui.Separator()
	if allowlistDiff.HasChanges() {
		ui.Info("Network allowlist:")
		ui.PrintDiff(allowlistDiff.Added, allowlistDiff.Removed)
	}
	if portsDiff.HasChanges() {
		ui.Info("Ports:")
		ui.PrintDiff(portsDiff.Added, portsDiff.Removed)
	}
	return ask("Continue with the updated policy? [y/N] ", false)
}

func ask(prompt string, defaultYes bool) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes
	}
	return line == "y" || line == "yes"
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringVar(&sandboxFlag, "sandbox", "", "Target sandbox name (default: read from policy file or remembered state)")
	syncCmd.Flags().BoolVar(&yesFlag, "yes", false, "Approve the sync without prompting (useful in CI)")
}
