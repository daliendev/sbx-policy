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
	Short: "Synchronize network allowlist with Docker Sandbox (alias for 'sync up')",
	RunE:  doSyncUp,
}

var syncUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Push .sbx/policy.yaml's network allowlist and ports to sbx",
	RunE:  doSyncUp,
}

var syncDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Pull the network allowlist and ports already configured in sbx into .sbx/policy.yaml",
	RunE:  doSyncDown,
}

// doSyncUp pushes .sbx/policy.yaml (the desired state) to sbx, warning when
// it differs from the last state we know sbx approved.
func doSyncUp(cmd *cobra.Command, args []string) error {
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

	ok, err := confirmSync(desiredAllowlist, desiredPorts, sandbox, stored.Allowlist, stored.Ports, found)
	if err != nil {
		return err
	}
	if !ok {
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

// doSyncDown pulls the network allowlist and ports already configured for
// the sandbox in sbx (the source of truth here) into .sbx/policy.yaml,
// warning when that would change the file.
func doSyncDown(cmd *cobra.Command, args []string) error {
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

	sandbox := resolveSandbox(sandboxFlag, ctx.policy.Sandbox, stored.Sandbox, found)
	if sandbox == "" {
		ui.Error("No sandbox specified for this project.")
		ui.Separator()
		ui.Info("sbx-policy sync down needs to know which sandbox to pull from.")
		ui.Separator()
		ui.Info("To specify a sandbox, use one of:")
		ui.Info("  1. Pass --sandbox <name> to sbx-policy sync down")
		ui.Info("  2. Add 'sandbox: <name>' to .sbx/policy.yaml")
		return fmt.Errorf("no sandbox specified")
	}

	client := sbx.NewClient()
	remoteAllowlist, err := client.ListNetworkRules(sandbox)
	if err != nil {
		return exitf("Error: %v\n", err)
	}
	remotePorts, err := client.ListPorts(sandbox)
	if err != nil {
		return exitf("Error: %v\n", err)
	}

	pulledAllowlist := policy.Normalize(remoteAllowlist)
	pulledPorts := policy.Normalize(remotePorts)
	allowlistDiff := policy.Compare(policy.Normalize(ctx.policy.NetworkAllowlist), pulledAllowlist)
	portsDiff := policy.Compare(policy.Normalize(ctx.policy.Ports), pulledPorts)

	if !allowlistDiff.HasChanges() && !portsDiff.HasChanges() {
		ui.Success(".sbx/policy.yaml already matches sandbox %s", sandbox)
		return nil
	}

	if !yesFlag {
		if !isStdinCharDevice() {
			ui.Error("This appears to be a non-interactive environment.")
			ui.Info("Use --yes to approve the pull without prompting.")
			return fmt.Errorf("non-interactive environment")
		}
		ui.Warning("Sandbox %s differs from .sbx/policy.yaml", sandbox)
		ui.Separator()
		if allowlistDiff.HasChanges() {
			ui.Info("Network allowlist:")
			ui.PrintDiff(allowlistDiff.Added, allowlistDiff.Removed)
		}
		if portsDiff.HasChanges() {
			ui.Info("Ports:")
			ui.PrintDiff(portsDiff.Added, portsDiff.Removed)
		}
		ui.Separator()
		if !ask("Overwrite .sbx/policy.yaml with the sandbox's current state? [y/N] ", false) {
			ui.Info("Aborted.")
			return fmt.Errorf("aborted")
		}
	}

	ctx.policy.NetworkAllowlist = pulledAllowlist
	ctx.policy.Ports = pulledPorts
	if err := config.Write(ctx.root, ctx.policy); err != nil {
		return err
	}

	if err := mgr.Save(key, state.ProjectState{Allowlist: pulledAllowlist, Sandbox: sandbox, Ports: pulledPorts}); err != nil {
		ui.Warning("Could not save remembered state: %v", err)
	}

	ui.Success(".sbx/policy.yaml updated from sandbox %s", sandbox)
	return nil
}

// isStdinCharDevice returns true when os.Stdin is a character device, as
// opposed to a pipe or file redirect. Note: this does not guarantee an
// interactive terminal (e.g. /dev/null is a character device).
func isStdinCharDevice() bool {
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
func confirmSync(desiredAllowlist, desiredPorts []string, sandbox string, storedAllowlist, storedPorts []string, found bool) (bool, error) {
	if yesFlag {
		return true, nil
	}

	allowlistDiff := policy.Compare(policy.Normalize(storedAllowlist), desiredAllowlist)
	portsDiff := policy.Compare(policy.Normalize(storedPorts), desiredPorts)
	noChanges := !allowlistDiff.HasChanges() && !portsDiff.HasChanges()

	if !found {
		if !isStdinCharDevice() {
			ui.Error("This appears to be a non-interactive environment.")
			ui.Info("Use --yes to approve the sync without prompting.")
			return false, fmt.Errorf("non-interactive environment")
		}
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
		return ask("Initialize and continue? [Y/n] ", true), nil
	}

	if noChanges {
		ui.Success("Network allowlist and ports unchanged for sandbox %s", sandbox)
		return true, nil
	}

	if !isStdinCharDevice() {
		ui.Error("This appears to be a non-interactive environment.")
		ui.Info("Use --yes to approve the sync without prompting.")
		return false, fmt.Errorf("non-interactive environment")
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
	return ask("Continue with the updated policy? [y/N] ", false), nil
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
	syncCmd.AddCommand(syncUpCmd)
	syncCmd.AddCommand(syncDownCmd)
	rootCmd.AddCommand(syncCmd)

	// Persistent so 'sync up' and 'sync down' inherit them alongside the
	// bare 'sync' (== 'sync up') alias.
	syncCmd.PersistentFlags().StringVar(&sandboxFlag, "sandbox", "", "Target sandbox name (default: read from policy file or remembered state)")
	syncCmd.PersistentFlags().BoolVar(&yesFlag, "yes", false, "Approve the sync without prompting (useful in CI)")
}
