package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencode/sbx-policy/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new .sbx/policy.yaml in the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		policyPath := config.PolicyFileName
		fullPath := filepath.Join(wd, policyPath)
		if _, err := os.Stat(fullPath); err == nil {
			fmt.Printf("✓ %s already exists\n", policyPath)
			return nil
		}

		p := config.DefaultPolicy()
		if err := config.Write(wd, p); err != nil {
			return err
		}

		fmt.Printf("✓ Created %s\n", policyPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
