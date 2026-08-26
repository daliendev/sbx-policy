package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/opencode/sbx-policy/internal/config"
)

// Validate checks that the policy conforms to the supported schema.
func Validate(p config.Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version: %d (expected 1)", p.Version)
	}

	if p.NetworkAllowlist == nil {
		return fmt.Errorf("network_allowlist must be a list")
	}

	for i, entry := range p.NetworkAllowlist {
		if strings.TrimSpace(entry) == "" {
			return fmt.Errorf("network_allowlist entry %d is empty", i)
		}
		if strings.Contains(entry, ",") {
			return fmt.Errorf("network_allowlist entry %q contains a comma", entry)
		}
		if strings.ContainsAny(entry, " \t\n\r") {
			return fmt.Errorf("network_allowlist entry %q contains whitespace", entry)
		}
	}

	return nil
}

// Normalize returns a sorted, deduplicated copy of the allowlist.
func Normalize(allowlist []string) []string {
	seen := make(map[string]struct{}, len(allowlist))
	out := make([]string, 0, len(allowlist))
	for _, entry := range allowlist {
		if _, ok := seen[entry]; !ok {
			seen[entry] = struct{}{}
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}

// Diff represents the difference between two allowlists.
type Diff struct {
	Added   []string
	Removed []string
}

// Compare returns the diff between two normalized allowlists.
func Compare(old, new []string) Diff {
	oldSet := make(map[string]struct{}, len(old))
	for _, e := range old {
		oldSet[e] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(new))
	for _, e := range new {
		newSet[e] = struct{}{}
	}

	var added, removed []string
	for _, e := range new {
		if _, ok := oldSet[e]; !ok {
			added = append(added, e)
		}
	}
	for _, e := range old {
		if _, ok := newSet[e]; !ok {
			removed = append(removed, e)
		}
	}

	return Diff{Added: added, Removed: removed}
}

// HasChanges returns true if the diff is non-empty.
func (d Diff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0
}

// Format returns a human-readable string representation of the diff.
func (d Diff) Format() string {
	var b strings.Builder
	for _, e := range d.Added {
		fmt.Fprintf(&b, "  + %s\n", e)
	}
	for _, e := range d.Removed {
		fmt.Fprintf(&b, "  - %s\n", e)
	}
	return b.String()
}
