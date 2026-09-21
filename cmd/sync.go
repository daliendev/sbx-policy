package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/reconcile"
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
	Args:  cobra.NoArgs,
	RunE:  doSyncUp,
}

var syncUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Push .sbx/policy.yaml's network allowlist and ports to sbx",
	Args:  cobra.NoArgs,
	RunE:  doSyncUp,
}

var syncDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Pull the network allowlist and ports already configured in sbx into .sbx/policy.yaml",
	Args:  cobra.NoArgs,
	RunE:  doSyncDown,
}

// syncSetup is the state shared by 'sync up' and 'sync down': the loaded
// project, the remembered-state manager, and the resolved target sandbox.
type syncSetup struct {
	ctx     projectContext
	mgr     *state.Manager
	key     string
	stored  state.ProjectState
	found   bool
	sandbox string
}

// prepareSync resolves the project and the target sandbox (CLI flag >
// policy file) — the setup shared by 'sync up' and 'sync down'. It prints
// guidance and returns an error when no sandbox can be resolved.
func prepareSync() (*syncSetup, error) {
	ctx, err := resolveProject()
	if err != nil {
		if errors.Is(err, config.ErrPolicyNotFound) {
			return nil, exitf("Error: %v\n\nRun 'sbx-policy init' to create one.\n", err)
		}
		return nil, exitf("Error: %v\n", err)
	}

	mgr := state.NewManager()
	key := ctx.identity.StateKey()
	stored, found, err := mgr.Load(key)
	if err != nil {
		ui.Warning("Could not load remembered state: %v", err)
	}

	sandbox := resolveSandbox(sandboxFlag, ctx.policy.Sandbox)
	if err := policy.ValidateSandboxName(sandbox); err != nil {
		return nil, exitf("Error: %v\n", err)
	}
	if sandbox == "" {
		ui.Error("No sandbox specified for this project.")
		ui.Separator()
		ui.Info("sbx-policy sync scopes network rules to individual sandboxes")
		ui.Info("instead of applying them globally.")
		ui.Separator()
		ui.Info("To specify a sandbox, use one of:")
		ui.Info("  1. Run 'sbx-policy sandbox set <name>' (writes it to .sbx/policy.yaml)")
		ui.Info("  2. Pass --sandbox <name> to sbx-policy sync")
		ui.Separator()
		ui.Info("To create a sandbox first, run your tool normally:")
		ui.Info("  sbx run <tool> .")
		return nil, fmt.Errorf("no sandbox specified")
	}

	return &syncSetup{ctx: ctx, mgr: mgr, key: key, stored: stored, found: found, sandbox: sandbox}, nil
}

// approval says how much of a sync plan the user has already agreed to.
type approval int

const (
	// askUser prompts before applying any non-empty plan.
	askUser approval = iota
	// approveAdditions applies without asking the additions the user just
	// requested with the command they ran (see runSyncUp's requested
	// argument). Anything else still asks: a removal, or an addition the
	// command did not ask for, can't come from that command, so it is sbx
	// drift or a hand edit of the policy file (possibly pulled from someone
	// else, or written by the agent running in the sandbox).
	approveAdditions
	// approveAll applies any plan without asking (--yes).
	approveAll
)

// needsPrompt reports whether plan must be confirmed by the user. requested
// is what the running command itself asked to add; it only matters for
// approveAdditions.
func (a approval) needsPrompt(plan reconcile.Plan, requested reconcile.Desired) bool {
	switch {
	case plan.Empty():
		return false
	case a == approveAll:
		return false
	case a == approveAdditions:
		return len(plan.RemoveRules) > 0 || len(plan.Unpublish) > 0 ||
			!containsAll(requested.Allowlist, plan.AddHosts) ||
			!containsAll(requested.Ports, plan.Publish)
	default:
		return true
	}
}

// containsAll reports whether every entry of want is in have.
func containsAll(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, e := range have {
		set[e] = struct{}{}
	}
	for _, e := range want {
		if _, ok := set[e]; !ok {
			return false
		}
	}
	return true
}

// doSyncUp is the 'sync' / 'sync up' entry point.
func doSyncUp(cmd *cobra.Command, args []string) error {
	if yesFlag {
		return runSyncUp(approveAll, reconcile.Desired{})
	}
	return runSyncUp(askUser, reconcile.Desired{})
}

// runSyncUp pushes .sbx/policy.yaml (the desired state) to sbx. It plans
// against sbx's actual state, shows what will change, and only then applies.
// requested lists what the calling command just added to the policy file, so
// approveAdditions can tell it apart from changes the user didn't ask for.
func runSyncUp(appr approval, requested reconcile.Desired) error {
	s, err := prepareSync()
	if err != nil {
		return err
	}

	desiredAllowlist := policy.Normalize(s.ctx.policy.NetworkAllowlist)
	desiredPorts := policy.Normalize(s.ctx.policy.Ports)

	svc := reconcile.New(sbx.NewClient())
	plan, err := svc.Plan(s.sandbox, reconcile.Desired{Allowlist: desiredAllowlist, Ports: desiredPorts})
	if err != nil {
		return exitf("Error: %v\n", err)
	}

	ok, err := confirmSync(plan, appr, requested, desiredAllowlist, desiredPorts, s.sandbox, s.stored.Allowlist, s.stored.Ports, s.found)
	if err != nil {
		return err
	}
	if !ok {
		ui.Info("Aborted.")
		return fmt.Errorf("aborted")
	}

	// %w keeps *reconcile.PublishError reachable for 'ports add' rollback.
	if err := svc.Apply(s.sandbox, plan); err != nil {
		return exitf("Error: %w\n", err)
	}

	if err := s.mgr.Save(s.key, state.ProjectState{Allowlist: desiredAllowlist, Ports: desiredPorts}); err != nil {
		ui.Warning("Could not save remembered state: %v", err)
	}

	if len(plan.SkippedRemovals) > 0 {
		ui.Warning("Could not remove from sbx (bundled with other hosts on the same rule; remove manually if needed):")
		ui.PrintList(plan.SkippedRemovals, "•")
	}

	ui.Success("Network allowlist and ports synchronized to sandbox %s", s.sandbox)
	return nil
}

// doSyncDown adopts the network allowlist and ports configured for the
// sandbox in sbx into .sbx/policy.yaml, warning when that would change the
// file. It is the explicit way to let sbx's state win over the file (e.g. to
// adopt an existing sandbox); entries the file already has and sbx still
// satisfies are left exactly as written.
func doSyncDown(cmd *cobra.Command, args []string) error {
	s, err := prepareSync()
	if err != nil {
		return err
	}

	svc := reconcile.New(sbx.NewClient())
	current, err := svc.Current(s.sandbox)
	if err != nil {
		return exitf("Error: %v\n", err)
	}

	// Adopt keeps the entries sbx still satisfies as written, so a bare
	// "3000" isn't rewritten to the host port sbx picked for it.
	adopted := reconcile.Adopt(reconcile.Desired{Allowlist: s.ctx.policy.NetworkAllowlist, Ports: s.ctx.policy.Ports}, current)
	pulledAllowlist := policy.Normalize(adopted.Allowlist)
	pulledPorts := policy.Normalize(adopted.Ports)
	allowlistDiff := policy.Compare(policy.Normalize(s.ctx.policy.NetworkAllowlist), pulledAllowlist)
	portsDiff := policy.Compare(policy.Normalize(s.ctx.policy.Ports), pulledPorts)
	changed := allowlistDiff.HasChanges() || portsDiff.HasChanges()

	if !changed {
		ui.Success(".sbx/policy.yaml already matches sandbox %s", s.sandbox)
	} else if !yesFlag {
		if err := requireInteractive(); err != nil {
			return err
		}
		ui.Warning("Sandbox %s differs from .sbx/policy.yaml", s.sandbox)
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
		if !ask("Update .sbx/policy.yaml with the sandbox's current state? [y/N] ", false) {
			ui.Info("Aborted.")
			return fmt.Errorf("aborted")
		}
	}

	if changed {
		s.ctx.policy.NetworkAllowlist = adopted.Allowlist
		s.ctx.policy.Ports = adopted.Ports
		if err := config.Write(s.ctx.root, s.ctx.policy); err != nil {
			return err
		}
	}

	// Always record the current state, even when nothing changed, so a
	// project pulled once (and never adopted a mismatched local edit)
	// doesn't keep re-triggering "no previous state" prompts on 'sync up'.
	if err := s.mgr.Save(s.key, state.ProjectState{Allowlist: pulledAllowlist, Ports: pulledPorts}); err != nil {
		ui.Warning("Could not save remembered state: %v", err)
	}

	if changed {
		ui.Success(".sbx/policy.yaml updated from sandbox %s", s.sandbox)
	}
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

// requireInteractive returns an error explaining that --yes is required
// when stdin isn't something sbx-policy can prompt on.
func requireInteractive() error {
	if isStdinCharDevice() {
		return nil
	}
	ui.Error("This appears to be a non-interactive environment.")
	ui.Info("Use --yes to approve without prompting.")
	return fmt.Errorf("non-interactive environment")
}

// resolveSandbox returns the effective sandbox name: the CLI flag if given,
// otherwise the policy file's. Deliberately no remembered-state fallback: the
// target must come from the versioned file or an explicit flag, never from
// a per-machine file the rest of the team doesn't have.
func resolveSandbox(flag, policySandbox string) string {
	if flag != "" {
		return flag
	}
	return policySandbox
}

// printPlan shows what applying plan will change in sbx.
func printPlan(plan reconcile.Plan) {
	if len(plan.AddHosts) > 0 || len(plan.RemoveRules) > 0 {
		ui.Info("Network allowlist:")
		ui.PrintDiff(plan.AddHosts, plan.RemovedHosts())
	}
	if len(plan.Publish) > 0 || len(plan.Unpublish) > 0 {
		ui.Info("Ports:")
		ui.PrintDiff(plan.Publish, plan.Unpublish)
	}
	if len(plan.SkippedRemovals) > 0 {
		ui.Info("Left in sbx (bundled with other hosts on the same rule):")
		ui.PrintList(plan.SkippedRemovals, "•")
	}
}

// confirmSync shows plan (what will actually change in sbx) and asks before
// applying it when appr requires it. The header says why the sync isn't a
// no-op: first sync, the policy file changed since the last approval, or sbx
// drifted from the policy file (someone changed it outside sbx-policy, and
// those changes will be undone). It returns true if the sync should proceed.
func confirmSync(plan reconcile.Plan, appr approval, requested reconcile.Desired, desiredAllowlist, desiredPorts []string, sandbox string, storedAllowlist, storedPorts []string, found bool) (bool, error) {
	if plan.Empty() {
		ui.Success("Sandbox %s already matches %s", sandbox, config.PolicyFileName)
		return true, nil
	}

	prompt := appr.needsPrompt(plan, requested)
	if prompt {
		if err := requireInteractive(); err != nil {
			return false, err
		}
	}

	fileChanged := found &&
		(policy.Compare(policy.Normalize(storedAllowlist), desiredAllowlist).HasChanges() ||
			policy.Compare(policy.Normalize(storedPorts), desiredPorts).HasChanges())
	switch {
	case !found:
		ui.Info("No previous network policy found for this project.")
	case fileChanged:
		ui.Warning("Policy changed since last approval")
	default:
		ui.Warning("Sandbox %s differs from %s (changed outside sbx-policy); syncing will undo that", sandbox, config.PolicyFileName)
	}
	ui.Separator()
	ui.Info("Sandbox: %s", sandbox)
	printPlan(plan)
	ui.Separator()

	if !prompt {
		return true, nil
	}
	// Removing anything from sbx is never the default answer, even on a first
	// sync: an empty line or EOF must not revoke rules or ports.
	destructive := len(plan.RemoveRules) > 0 || len(plan.Unpublish) > 0
	switch {
	case !found && destructive:
		return ask("Initialize and continue (this removes entries from sbx)? [y/N] ", false), nil
	case !found:
		return ask("Initialize and continue? [Y/n] ", true), nil
	default:
		return ask("Continue with these changes? [y/N] ", false), nil
	}
}

// stdin is shared by every prompt: a reader per call would buffer past the
// first line and swallow the answer to the next question when input is piped.
var stdin = bufio.NewReader(os.Stdin)

func ask(prompt string, defaultYes bool) bool {
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
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
	syncCmd.PersistentFlags().StringVar(&sandboxFlag, "sandbox", "", "Target sandbox name (default: sandbox from .sbx/policy.yaml)")
	syncCmd.PersistentFlags().BoolVar(&yesFlag, "yes", false, "Approve the sync without prompting (useful in CI)")
}
