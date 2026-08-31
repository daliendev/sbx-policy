package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrPolicyNotFound is returned when FindProjectRoot cannot locate a policy file.
var ErrPolicyNotFound = errors.New("policy file not found")

const PolicyFileName = ".sbx/policy.yaml"

type Policy struct {
	Version          int      `yaml:"version"`
	Sandbox          string   `yaml:"sandbox,omitempty"`
	NetworkAllowlist []string `yaml:"network_allowlist"`
	Ports            []string `yaml:"ports,omitempty"`
}

// DefaultPolicy returns the initial policy content.
func DefaultPolicy() Policy {
	return Policy{
		Version:          1,
		NetworkAllowlist: []string{},
		Ports:            []string{},
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

	return "", fmt.Errorf("%w: no %s found", ErrPolicyNotFound, PolicyFileName)
}

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
