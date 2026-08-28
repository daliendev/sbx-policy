package sbx

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner abstracts execution of external commands so tests can substitute a mock.
type Runner interface {
	Run(name string, arg ...string) ([]byte, error)
	RunInteractive(name string, arg ...string) error
}

// RealRunner is the production implementation that shells out to sbx.
type RealRunner struct{}

func (r *RealRunner) Run(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	return cmd.CombinedOutput()
}

func (r *RealRunner) RunInteractive(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Client wraps interactions with the sbx CLI.
type Client struct {
	Runner Runner
}

// NewClient creates a Client with the real runner.
func NewClient() *Client {
	return &Client{Runner: &RealRunner{}}
}

// ListNetworkRules returns the current network allowlist entries managed by sbx.
//
// LIMITATION: sbx does not currently expose a structured way to list only network
// policy rules with their provenance. We attempt to parse the output of
// "sbx policy ls" and filter for lines that look like network allowances.
// If the CLI output format changes, this may break.
func (c *Client) ListNetworkRules() ([]string, error) {
	out, err := c.Runner.Run("sbx", "policy", "ls")
	if err != nil {
		// If sbx doesn't support "policy ls", we can't determine current state.
		return nil, fmt.Errorf("sbx policy ls failed: %w", err)
	}

	var rules []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Heuristic: look for lines that mention "allow network" and extract the host.
		if strings.Contains(line, "allow") && strings.Contains(line, "network") {
			parts := strings.Fields(line)
			for _, p := range parts {
				// Rough extraction of host-like tokens.
				if strings.Contains(p, ".") || strings.Contains(p, "*") {
					rules = append(rules, strings.Trim(p, "\"'"))
				}
			}
		}
	}
	return rules, scanner.Err()
}

// AddNetworkRule adds a single network allowlist entry via sbx.
func (c *Client) AddNetworkRule(host string) error {
	out, err := c.Runner.Run("sbx", "policy", "allow", "network", host)
	if err != nil {
		return fmt.Errorf("sbx policy allow network %s: %w\noutput: %s", host, err, string(out))
	}
	return nil
}

// RemoveNetworkRule removes a single network allowlist entry via sbx.
// NOTE: sbx may not support removing individual rules. This is a placeholder
// for future CLI support.
func (c *Client) RemoveNetworkRule(host string) error {
	// As of the current sbx CLI, there is no known "remove" subcommand.
	// We silently skip removal to avoid destroying global rules.
	return nil
}

// SyncNetworkPolicy ensures the given allowlist is present in sbx.
// It is idempotent: repeated calls with the same list do not keep adding rules.
func (c *Client) SyncNetworkPolicy(desired []string) error {
	current, err := c.ListNetworkRules()
	if err != nil {
		// LIMITATION: If we can't read current state, we add rules defensively.
		// We skip removal because we can't verify ownership.
		for _, h := range desired {
			_ = c.AddNetworkRule(h)
		}
		return fmt.Errorf("unable to read current sbx state; added desired rules defensively: %w", err)
	}

	currentSet := make(map[string]struct{}, len(current))
	for _, h := range current {
		currentSet[h] = struct{}{}
	}

	for _, h := range desired {
		if _, ok := currentSet[h]; !ok {
			if err := c.AddNetworkRule(h); err != nil {
				return err
			}
		}
	}

	return nil
}


