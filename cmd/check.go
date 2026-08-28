package cmd

import (
	"fmt"
	"os"

	"github.com/opencode/sbx-policy/internal/config"
	"github.com/opencode/sbx-policy/internal/policy"
	"github.com/opencode/sbx-policy/internal/project"
	"github.com/opencode/sbx-policy/internal/state"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Validate .sbx/policy.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
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
		stored, found, _ := mgr.Load(identity.StateKey())

		sandbox := p.Sandbox
		if sandbox == "" && found {
			sandbox = stored.Sandbox
		}

		if sandbox != "" {
			fmt.Printf("✓ .sbx/policy.yaml is valid (sandbox: %s)\n", sandbox)
		} else {
			fmt.Println("✓ .sbx/policy.yaml is valid")
			fmt.Fprintln(os.Stderr, "⚠ Warning: no sandbox configured. 'sbx-policy sync' will fail until you set one.")
			fmt.Fprintln(os.Stderr, "   Add 'sandbox: <name>' to .sbx/policy.yaml or pass --sandbox to sync.")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
