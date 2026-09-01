package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/daliendev/sbx-policy/internal/config"
	"github.com/daliendev/sbx-policy/internal/policy"
	"github.com/daliendev/sbx-policy/internal/project"
	"github.com/daliendev/sbx-policy/internal/ui"
)

type projectContext struct {
	root     string
	policy   config.Policy
	identity project.Identity
}

// resolveProject determines the project root, loads and validates the policy,
// and identifies the project. It is used by any command that needs the full
// project context (check, sync, etc.).
func resolveProject() (projectContext, error) {
	wd, err := os.Getwd()
	if err != nil {
		return projectContext{}, fmt.Errorf("get working directory: %w", err)
	}

	root, err := config.FindProjectRoot(wd)
	if err != nil {
		return projectContext{}, err
	}

	p, err := config.Load(root)
	if err != nil {
		return projectContext{}, err
	}

	if err := policy.Validate(p); err != nil {
		return projectContext{}, err
	}

	id, err := project.Identify(root)
	if err != nil {
		return projectContext{}, fmt.Errorf("identify project: %w", err)
	}

	return projectContext{root: root, policy: p, identity: id}, nil
}

// exitf returns a formatted error.
func exitf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// splitCommaSeparated flattens each arg by splitting it on commas and
// trimming surrounding whitespace, so "a.com,b.com" and "a.com b.com" (and
// any mix of the two) both expand to the same set of entries.
func splitCommaSeparated(args []string) []string {
	var out []string
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			out = append(out, part)
		}
	}
	return out
}

// addUnique appends entries that are not already present in list.
// It returns the updated list and the entries that were actually added.
func addUnique(list []string, entries []string) ([]string, []string) {
	seen := make(map[string]struct{}, len(list))
	for _, e := range list {
		seen[e] = struct{}{}
	}
	var added []string
	for _, e := range entries {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		list = append(list, e)
		added = append(added, e)
	}
	return list, added
}

// offerSync prompts the user to run 'sbx-policy sync' immediately when stdin
// is interactive; otherwise it prints a hint to run sync manually.
// The sync runs with auto-approval to avoid a second confirmation prompt.
func offerSync() error {
	if !isStdinCharDevice() {
		ui.Info("Run 'sbx-policy sync' to apply the changes.")
		return nil
	}
	if !ask("Run 'sbx-policy sync' now? [Y/n] ", true) {
		ui.Info("Run 'sbx-policy sync' to apply the changes.")
		return nil
	}
	yesFlag = true
	defer func() { yesFlag = false }()
	return doSyncUp(nil, nil)
}
