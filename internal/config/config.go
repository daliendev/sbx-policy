package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const PolicyFileName = ".sbx/policy.yaml"

// Policy represents the project policy file schema.
type Policy struct {
	Version          int      `yaml:"version"`
	Sandbox          string   `yaml:"sandbox,omitempty"`
	NetworkAllowlist []string `yaml:"network_allowlist"`
}

// DefaultPolicy returns the initial policy content.
func DefaultPolicy() Policy {
	return Policy{
		Version:          1,
		NetworkAllowlist: []string{},
	}
}

// FindProjectRoot walks upward from startDir until it finds a directory
// containing .sbx/policy.yaml.
func FindProjectRoot(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, PolicyFileName)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("no %s found", PolicyFileName)
}

// Load reads and parses the policy file from the given project root.
func Load(projectRoot string) (Policy, error) {
	path := filepath.Join(projectRoot, PolicyFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy file: %w", err)
	}

	return p, nil
}

// Write writes the policy file to the given project root.
func Write(projectRoot string, p Policy) error {
	path := filepath.Join(projectRoot, PolicyFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}

	data, err := yaml.Marshal(&p)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}

	return nil
}
