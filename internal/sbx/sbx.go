package sbx

import (
	"bufio"
	"bytes"
	"encoding/json"
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

// policyRule mirrors one entry in the "rules" array returned by
// "sbx policy ls <sandbox> --type network --json".
type policyRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	PolicyID     string   `json:"policy_id"`
	Scope        string   `json:"scope"`
	AppliesTo    string   `json:"applies_to"`
	ResourceType string   `json:"resource_type"`
	Decision     string   `json:"decision"`
	Resources    []string `json:"resources"`
	Origin       string   `json:"origin"`
	Layer        string   `json:"layer"`
	Status       string   `json:"status"`
	Editable     bool     `json:"editable"`
	SandboxID    string   `json:"sandbox_id"`
}

type policyLsResponse struct {
	Rules []policyRule `json:"rules"`
}

// networkRule is a single host-level allow rule that sbx currently has
// scoped to a sandbox, with enough information to remove it precisely.
// ID is empty when the rule bundles more than one resource under a single
// rule ID (as kit-provided policies sometimes do) and therefore cannot be
// narrowed to a single host by ID.
type networkRule struct {
	ID   string
	Host string
}

// listScopedNetworkRules returns the network allow rules that sbx currently
// has scoped specifically to the given sandbox (scope "sandbox:<sandbox>",
// decision "allow", editable).
//
// Global/kit-provided defaults (scope "global", applies_to "all", e.g. the
// default package-manager/cloud-infra bundles) are deliberately excluded:
// they apply to every sandbox on the host and are not something a single
// project's policy.yaml should own or ever attempt to remove. Mixing them
// into the diff used by SyncNetworkPolicy would make "sync up" try to
// revoke hundreds of unrelated default domains the moment they are absent
// from a project's small network_allowlist.
func (c *Client) listScopedNetworkRules(sandbox string) ([]networkRule, error) {
	if sandbox == "" {
		return nil, fmt.Errorf("sandbox name is required to list scoped network rules")
	}

	// The sandbox is a positional argument to "sbx policy ls", not a flag —
	// "sbx policy ls --sandbox <name>" is rejected with "unknown flag".
	args := []string{"policy", "ls", sandbox, "--type", "network", "--json"}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return nil, fmt.Errorf("sbx policy ls %s --type network --json failed: %w\noutput: %s", sandbox, err, string(out))
	}

	var resp policyLsResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse sbx policy ls --json output: %w\noutput: %s", err, string(out))
	}

	wantScope := "sandbox:" + sandbox
	var rules []networkRule
	for _, r := range resp.Rules {
		if r.ResourceType != "network" || r.Decision != "allow" || !r.Editable {
			continue
		}
		if r.Scope != wantScope {
			continue
		}
		id := r.ID
		if len(r.Resources) != 1 {
			// A bundled rule: removing by ID would take every resource
			// with it, so per-host removal isn't safe here.
			id = ""
		}
		for _, host := range r.Resources {
			rules = append(rules, networkRule{ID: id, Host: host})
		}
	}
	return rules, nil
}

// ListNetworkRules returns the network allowlist entries that sbx currently
// has scoped to the given sandbox. See listScopedNetworkRules for exactly
// what is (and isn't) included.
func (c *Client) ListNetworkRules(sandbox string) ([]string, error) {
	rules, err := c.listScopedNetworkRules(sandbox)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(rules))
	for _, r := range rules {
		hosts = append(hosts, r.Host)
	}
	return hosts, nil
}

// AddNetworkRule adds a single network allowlist entry via sbx.
// If sandbox is non-empty, the rule is scoped to that sandbox only.
func (c *Client) AddNetworkRule(host string, sandbox string) error {
	return c.AddNetworkRules([]string{host}, sandbox)
}

// AddNetworkRules adds one or more network allowlist entries via sbx in a
// single CLI invocation. If sandbox is non-empty, the rule is scoped to that
// sandbox only.
func (c *Client) AddNetworkRules(hosts []string, sandbox string) error {
	if len(hosts) == 0 {
		return nil
	}
	args := []string{"policy", "allow", "network"}
	if sandbox != "" {
		args = append(args, "--sandbox", sandbox)
	}
	joined := strings.Join(hosts, ",")
	args = append(args, joined)
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx policy allow network %s: %w\noutput: %s", joined, err, string(out))
	}
	return nil
}

// RemoveNetworkRuleByID removes a single network allow rule via its rule
// ID, as returned by ListNetworkRules/listScopedNetworkRules. This deletes
// the rule outright (via "sbx policy rm network --id"), unlike adding a
// deny rule on top, which would leave the original allow rule in place.
// Sandbox is required because the removal is scoped to it.
func (c *Client) RemoveNetworkRuleByID(ruleID string, sandbox string) error {
	if sandbox == "" {
		return fmt.Errorf("sandbox name is required to remove a network rule")
	}
	args := []string{"policy", "rm", "network", "--id", ruleID, "--sandbox", sandbox}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return fmt.Errorf("sbx policy rm network --id %s --sandbox %s: %w\noutput: %s", ruleID, sandbox, err, string(out))
	}
	return nil
}

// SyncNetworkPolicy ensures the given allowlist is present in sbx, scoped to
// sandbox, and that any rule previously scoped there but no longer in
// desired is removed outright. It is idempotent: repeated calls with the
// same list do not keep adding or removing rules.
func (c *Client) SyncNetworkPolicy(desired []string, sandbox string) error {
	current, err := c.listScopedNetworkRules(sandbox)
	if err != nil {
		allErrs := []error{err}
		if addErr := c.AddNetworkRules(desired, sandbox); addErr != nil {
			allErrs = append(allErrs, addErr)
		}
		return fmt.Errorf("unable to read current sbx state; attempted to add desired rules defensively: %w", errors.Join(allErrs...))
	}

	currentByHost := make(map[string]string, len(current)) // host -> ruleID ("" if not individually removable)
	for _, r := range current {
		currentByHost[r.Host] = r.ID
	}

	desiredSet := make(map[string]struct{}, len(desired))
	for _, h := range desired {
		desiredSet[h] = struct{}{}
	}

	var toAdd []string
	for _, h := range desired {
		if _, ok := currentByHost[h]; !ok {
			toAdd = append(toAdd, h)
		}
	}
	if len(toAdd) > 0 {
		if err := c.AddNetworkRules(toAdd, sandbox); err != nil {
			return err
		}
	}

	for host, ruleID := range currentByHost {
		if _, ok := desiredSet[host]; ok {
			continue
		}
		if ruleID == "" {
			// Part of a bundled rule we can't safely narrow to this host
			// alone; leave it alone rather than risk removing siblings.
			continue
		}
		if err := c.RemoveNetworkRuleByID(ruleID, sandbox); err != nil {
			return err
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
