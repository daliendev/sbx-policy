package sbx

import (
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

// SyncResult reports outcomes of SyncNetworkPolicy that a caller may need to
// surface but that aren't errors.
type SyncResult struct {
	// SkippedRemovals lists hosts that should have been removed (they were
	// present in sbx but not in the desired list) but couldn't be, because
	// they belong to a rule that bundles more than one resource under a
	// single ID — removing it would take its siblings with it.
	SkippedRemovals []string
}

// SyncNetworkPolicy ensures the given allowlist is present in sbx, scoped to
// sandbox, and that any rule previously scoped there but no longer in
// desired is removed outright. It is idempotent: repeated calls with the
// same list do not keep adding or removing rules.
func (c *Client) SyncNetworkPolicy(desired []string, sandbox string) (SyncResult, error) {
	current, err := c.listScopedNetworkRules(sandbox)
	if err != nil {
		allErrs := []error{err}
		if addErr := c.AddNetworkRules(desired, sandbox); addErr != nil {
			allErrs = append(allErrs, addErr)
		}
		return SyncResult{}, fmt.Errorf("unable to read current sbx state; attempted to add desired rules defensively: %w", errors.Join(allErrs...))
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
			return SyncResult{}, err
		}
	}

	var result SyncResult
	for host, ruleID := range currentByHost {
		if _, ok := desiredSet[host]; ok {
			continue
		}
		if ruleID == "" {
			// Part of a bundled rule we can't safely narrow to this host
			// alone; leave it alone rather than risk removing siblings.
			result.SkippedRemovals = append(result.SkippedRemovals, host)
			continue
		}
		if err := c.RemoveNetworkRuleByID(ruleID, sandbox); err != nil {
			return result, err
		}
	}

	return result, nil
}

// portMapping mirrors one entry in the array returned by
// "sbx ports <sandbox> --json".
type portMapping struct {
	HostIP      string `json:"host_ip"`
	HostPort    int    `json:"host_port"`
	SandboxPort int    `json:"sandbox_port"`
	Protocol    string `json:"protocol"`
}

// ListPorts returns the current port mappings for a sandbox, as
// "hostPort:sandboxPort" strings.
//
// "sbx ports --publish" binds a port on every IP family the sandbox has by
// default (127.0.0.1 and ::1 for a dual-stack sandbox), so a single publish
// shows up as multiple entries in the daemon's response that only differ by
// host_ip. Those are deliberately collapsed into one mapping here: from
// policy.yaml's point of view there is exactly one port mapping, regardless
// of how many IP families it's bound on. Protocol is ignored for the same
// reason — policy.yaml's mapping format (see ValidatePortMapping) has no way
// to express it, so sbx-policy never manages per-protocol entries.
func (c *Client) ListPorts(sandbox string) ([]string, error) {
	if sandbox == "" {
		return nil, fmt.Errorf("sandbox name is required to list ports")
	}

	args := []string{"ports", sandbox, "--json"}
	out, err := c.Runner.Run("sbx", args...)
	if err != nil {
		return nil, fmt.Errorf("sbx ports %s --json failed: %w\noutput: %s", sandbox, err, string(out))
	}

	var mappings []portMapping
	if err := json.Unmarshal(out, &mappings); err != nil {
		return nil, fmt.Errorf("parse sbx ports --json output: %w\noutput: %s", err, string(out))
	}

	seen := make(map[string]struct{}, len(mappings))
	var ports []string
	for _, m := range mappings {
		mapping := fmt.Sprintf("%d:%d", m.HostPort, m.SandboxPort)
		if _, ok := seen[mapping]; ok {
			continue
		}
		seen[mapping] = struct{}{}
		ports = append(ports, mapping)
	}
	return ports, nil
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
