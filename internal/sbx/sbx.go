package sbx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner abstracts execution of external commands so tests can substitute a mock.
type Runner interface {
	Run(name string, arg ...string) ([]byte, error)
}

// RealRunner is the production implementation that shells out to sbx.
type RealRunner struct{}

func (r *RealRunner) Run(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	return cmd.CombinedOutput()
}

// Client wraps interactions with the sbx CLI.
type Client struct {
	Runner Runner
}

func NewClient() *Client {
	return &Client{Runner: &RealRunner{}}
}

// ListNetworkRules returns the current network allowlist entries managed by sbx.
// If sandbox is non-empty, rules are scoped to that sandbox.
//
// LIMITATION: sbx does not currently expose a structured way to list only network
// policy rules with their provenance. We attempt to parse the output of
// "sbx policy ls" and filter for lines that look like network allowances.
// If the CLI output format changes, this may break.
func (c *Client) ListNetworkRules(sandbox string) ([]string, error) {
	args := []string{"policy", "ls"}
	if sandbox != "" {
		args = append(args, "--sandbox", sandbox)
	}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return nil, fmt.Errorf("sbx policy ls failed: %w", err)
	}

	var rules []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Heuristic: look for lines that mention "allow" and "network" and extract the host.
		if strings.Contains(line, "allow") && strings.Contains(line, "network") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, ".") || strings.Contains(p, "*") {
					rules = append(rules, strings.Trim(p, "\"'"))
				}
			}
		}
	}
	return rules, scanner.Err()
}

// AddNetworkRule adds a single network allowlist entry via sbx.
// If sandbox is non-empty, the rule is scoped to that sandbox only.
func (c *Client) AddNetworkRule(host string, sandbox string) error {
	args := []string{"policy", "allow", "network"}
	if sandbox != "" {
		args = append(args, "--sandbox", sandbox)
	}
	args = append(args, host)
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx policy allow network %s: %w\noutput: %s", host, err, string(out))
	}
	return nil
}

// RemoveNetworkRule removes a single network allowlist entry via sbx.
// If sandbox is non-empty, the rule is scoped to that sandbox only.
func (c *Client) RemoveNetworkRule(host string, sandbox string) error {
	args := []string{"policy", "deny", "network"}
	if sandbox != "" {
		args = append(args, "--sandbox", sandbox)
	}
	args = append(args, host)
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx policy deny network %s: %w\noutput: %s", host, err, string(out))
	}
	return nil
}

// SyncNetworkPolicy ensures the given allowlist is present in sbx.
// If sandbox is non-empty, the policy is scoped to that sandbox only.
// It is idempotent: repeated calls with the same list do not keep adding rules.
func (c *Client) SyncNetworkPolicy(desired []string, sandbox string) error {
	current, err := c.ListNetworkRules(sandbox)
	if err != nil {
		allErrs := []error{err}
		for _, h := range desired {
			if addErr := c.AddNetworkRule(h, sandbox); addErr != nil {
				allErrs = append(allErrs, addErr)
			}
		}
		return fmt.Errorf("unable to read current sbx state; attempted to add desired rules defensively: %w", errors.Join(allErrs...))
	}

	currentSet := make(map[string]struct{}, len(current))
	for _, h := range current {
		currentSet[h] = struct{}{}
	}

	desiredSet := make(map[string]struct{}, len(desired))
	for _, h := range desired {
		desiredSet[h] = struct{}{}
	}

	for _, h := range desired {
		if _, ok := currentSet[h]; !ok {
			if err := c.AddNetworkRule(h, sandbox); err != nil {
				return err
			}
		}
	}

	for _, h := range current {
		if _, ok := desiredSet[h]; !ok {
			if err := c.RemoveNetworkRule(h, sandbox); err != nil {
				return err
			}
		}
	}

	return nil
}

// ListPorts returns the current port mappings for a sandbox.
//
// LIMITATION: sbx does not expose a structured API for port mappings.
// We parse the output of "sbx ls" and look for tokens like "8080->3000/tcp".
func (c *Client) ListPorts(sandbox string) ([]string, error) {
	out, err := c.Runner.Run("sbx", "ls")
	if err != nil {
		return nil, fmt.Errorf("sbx ls failed: %w", err)
	}

	var ports []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			firstLine = false
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Only look at lines that mention the requested sandbox.
		if sandbox != "" && fields[0] != sandbox {
			continue
		}
		// Heuristic: look for port mapping tokens like "127.0.0.1:8080->3000/tcp"
		for _, field := range fields {
			if !strings.Contains(field, "->") {
				continue
			}
			mapping := strings.TrimSuffix(field, "/tcp")
			mapping = strings.TrimSuffix(mapping, "/tcp4")
			mapping = strings.TrimSuffix(mapping, "/tcp6")
			mapping = strings.TrimSuffix(mapping, "/udp")
			// Extract host:sandbox from "127.0.0.1:8080->3000" → "8080:3000"
			idx := strings.LastIndex(mapping, "->")
			if idx == -1 {
				continue
			}
			sandboxPort := mapping[idx+2:]
			before := mapping[:idx]
			hostPort := before
			if colon := strings.LastIndex(before, ":"); colon != -1 {
				hostPort = before[colon+1:]
			}
			if hostPort != "" && sandboxPort != "" {
				ports = append(ports, hostPort+":"+sandboxPort)
			}
		}
	}
	return ports, scanner.Err()
}

// PublishPort publishes a port mapping for a sandbox.
func (c *Client) PublishPort(mapping string, sandbox string) error {
	if sandbox == "" {
		return fmt.Errorf("sandbox name is required to publish ports")
	}
	args := []string{"ports", sandbox, "--publish", mapping}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx ports %s --publish %s: %w\noutput: %s", sandbox, mapping, err, string(out))
	}
	return nil
}

// UnpublishPort removes a port mapping for a sandbox.
func (c *Client) UnpublishPort(mapping string, sandbox string) error {
	if sandbox == "" {
		return fmt.Errorf("sandbox name is required to unpublish ports")
	}
	args := []string{"ports", sandbox, "--unpublish", mapping}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx ports %s --unpublish %s: %w\noutput: %s", sandbox, mapping, err, string(out))
	}
	return nil
}

// SyncPorts ensures the given port mappings are present for a sandbox.
// It is idempotent: repeated calls with the same list do not keep adding rules.
// Bare ports like "3000" match any current mapping whose sandbox port is 3000.
func (c *Client) SyncPorts(desired []string, sandbox string) error {
	current, err := c.ListPorts(sandbox)
	if err != nil {
		allErrs := []error{err}
		for _, m := range desired {
			if pubErr := c.PublishPort(m, sandbox); pubErr != nil {
				allErrs = append(allErrs, pubErr)
			}
		}
		return fmt.Errorf("unable to read current sbx ports; attempted to add desired ports defensively: %w", errors.Join(allErrs...))
	}

	// Determine which current ports are matched by desired
	currentMatched := make(map[int]struct{}, len(current))
	for i, cur := range current {
		for _, d := range desired {
			if portMatchesDesired(cur, d) {
				currentMatched[i] = struct{}{}
				break
			}
		}
	}

	// Remove unmatched current ports
	for i, cur := range current {
		if _, ok := currentMatched[i]; !ok {
			if err := c.UnpublishPort(cur, sandbox); err != nil {
				return err
			}
		}
	}

	// Add desired ports that don't have a match in current
	for _, d := range desired {
		matched := false
		for _, cur := range current {
			if portMatchesDesired(cur, d) {
				matched = true
				break
			}
		}
		if !matched {
			if err := c.PublishPort(d, sandbox); err != nil {
				return err
			}
		}
	}

	return nil
}

// portMatchesDesired reports whether a current port mapping satisfies a
// desired entry. An exact match always satisfies. Additionally, a bare
// desired port like "3000" matches any current mapping whose sandbox
// port is 3000 (e.g. "49152:3000"), reflecting Docker-style behaviour.
func portMatchesDesired(current, desired string) bool {
	if current == desired {
		return true
	}
	if !strings.Contains(desired, ":") {
		return strings.HasSuffix(current, ":"+desired)
	}
	return false
}
