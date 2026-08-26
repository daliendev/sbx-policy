package project

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Identity holds the information used to identify a project robustly.
type Identity struct {
	Root string `json:"root"` // Absolute path to project root
	Name string `json:"name"` // Git remote origin URL or directory name
}

// Identify attempts to determine a stable project identity.
// It prefers the Git repository root and remote origin URL.
func Identify(startDir string) (Identity, error) {
	root, err := findGitRoot(startDir)
	if err != nil {
		// Fall back to the directory containing .sbx/policy.yaml
		root = startDir
	}

	name, err := gitRemoteOrigin(root)
	if err != nil {
		name = filepath.Base(root)
	} else {
		name = normalizeGitURL(name)
	}

	// Normalize name for safe filesystem usage
	name = strings.TrimSuffix(name, ".git")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ":", "-")

	return Identity{
		Root: root,
		Name: name,
	}, nil
}

// StateKey returns a unique key for storing state for this project.
func (id Identity) StateKey() string {
	// Use both the sanitized name and a hash of the absolute path
	// to avoid collisions when two projects share the same name.
	return fmt.Sprintf("%s-%x", id.Name, hashString(id.Root))
}

// normalizeGitURL extracts a "host/path" identifier from common git remote URLs.
// Examples:
//
//	https://github.com/opencode/sbx-policy.git   -> github.com/opencode/sbx-policy
//	git@github.com:opencode/sbx-policy.git       -> github.com/opencode/sbx-policy
//	ssh://git@github.com/opencode/sbx-policy.git -> github.com/opencode/sbx-policy
func normalizeGitURL(raw string) string {
	// SSH style: git@github.com:org/repo.git
	if strings.HasPrefix(raw, "git@") {
		withoutPrefix := strings.TrimPrefix(raw, "git@")
		parts := strings.SplitN(withoutPrefix, ":", 2)
		if len(parts) == 2 {
			return parts[0] + "/" + parts[1]
		}
	}

	// URL style: https://github.com/org/repo.git or ssh://git@host/path
	if strings.Contains(raw, "://") {
		// Strip scheme
		parts := strings.SplitN(raw, "://", 2)
		if len(parts) == 2 {
			return strings.TrimPrefix(parts[1], "git@")
		}
	}

	return raw
}

func findGitRoot(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitRemoteOrigin(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Simple string hash for disambiguation.
func hashString(s string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}
