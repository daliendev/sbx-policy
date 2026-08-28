package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/opencode/sbx-policy/internal/config"
	"github.com/opencode/sbx-policy/internal/policy"
	"github.com/opencode/sbx-policy/internal/project"
	"github.com/opencode/sbx-policy/internal/sbx"
	"github.com/opencode/sbx-policy/internal/state"
	"github.com/spf13/cobra"
)

var sandboxFlag string

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize network allowlist with Docker Sandbox",
	RunE:  doSync,
}

func doSync(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	root, err := config.FindProjectRoot(wd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n\nRun 'sbx-policy init' to create one.\n", err)
		os.Exit(1)
	}

	p, err := config.Load(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := policy.Validate(p); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	identity, err := project.Identify(root)
	if err != nil {
		return fmt.Errorf("identify project: %w", err)
	}

	mgr := state.NewManager()
	key := identity.StateKey()
	stored, found, err := mgr.Load(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load remembered state: %v\n", err)
	}

	desired := policy.Normalize(p.NetworkAllowlist)

	// Resolve sandbox: CLI flag > policy file > remembered state
	sandbox := sandboxFlag
	if sandbox == "" {
		sandbox = p.Sandbox
	}
	if sandbox == "" && found {
		sandbox = stored.Sandbox
	}

	if sandbox == "" {
		fmt.Fprintln(os.Stderr, "Error: No sandbox specified for this project.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "sbx-policy sync scopes network rules to individual sandboxes")
		fmt.Fprintln(os.Stderr, "instead of applying them globally.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "To specify a sandbox, use one of:")
		fmt.Fprintln(os.Stderr, "  1. Pass --sandbox <name> to sbx-policy sync")
		fmt.Fprintln(os.Stderr, "  2. Add 'sandbox: <name>' to .sbx/policy.yaml")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "To create a sandbox first, run your tool normally:")
		fmt.Fprintln(os.Stderr, "  sbx run <tool> .")
		os.Exit(1)
	}

	confirmed := false

	if !found {
		fmt.Printf("No previous network policy found for this project.\n\n")
		fmt.Printf("Sandbox: %s\n", sandbox)
		fmt.Println("Network allowlist:")
		for _, e := range desired {
			fmt.Printf("  • %s\n", e)
		}
		fmt.Println()
		if ask("Initialize and continue? [Y/n] ", true) {
			confirmed = true
		}
	} else {
		storedNorm := policy.Normalize(stored.Allowlist)
		diff := policy.Compare(storedNorm, desired)
		if diff.HasChanges() {
			fmt.Println("⚠ Network allowlist changed since last approval")
			fmt.Println()
			fmt.Printf("Sandbox: %s\n", sandbox)
			fmt.Println()
			fmt.Print(diff.Format())
			fmt.Println()
			if ask("Continue with the updated policy? [y/N] ", false) {
				confirmed = true
			}
		} else {
			fmt.Printf("✓ Network allowlist unchanged for sandbox %s\n", sandbox)
			confirmed = true
		}
	}

	if !confirmed {
		fmt.Println("Aborted.")
		os.Exit(1)
	}

	if err := mgr.Save(key, state.ProjectState{Allowlist: desired, Sandbox: sandbox}); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save remembered state: %v\n", err)
	}

	client := sbx.NewClient()
	if err := client.SyncNetworkPolicy(desired, sandbox); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Network allowlist synchronized to sandbox %s\n", sandbox)
	return nil
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
}
