package sbx

import (
	"bytes"
	"encoding/json"
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

// Run executes sbx and returns stdout only. stdout and stderr are captured
// separately (not via CombinedOutput) because sbx sometimes writes an
// unrelated banner (e.g. an update notice) to stderr after a command
// finishes; merging the two streams appends that banner right after JSON
// written to stdout, which breaks json.Unmarshal (e.g. "invalid character
// '╭' after top-level value" from "sbx policy ls --json"). On failure,
// stderr is folded into the returned error so callers still get useful
// diagnostics.
func (r *RealRunner) Run(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), err
}

// Client wraps interactions with the sbx CLI.
type Client struct {
	Runner Runner
}

func NewClient() *Client {
	return &Client{Runner: &RealRunner{}}
}

// decodeJSONValue decodes the first top-level JSON value in b into v,
// ignoring anything before or after it. Separating stdout from stderr (see
// RealRunner.Run) stops sbx's update-notice banner from being appended when
// it's written to stderr, but sbx has also been observed writing that same
// banner to stdout — before or after the JSON it prints for a --json
// command. json.Unmarshal rejects that outright ("invalid character '╭'
// after top-level value"); a Decoder reads only one JSON value and leaves
// the rest alone, so a banner on either side of it no longer breaks parsing.
//
// A leading banner may itself contain "{" or "[" (e.g. "[v1.2 available]"),
// so every candidate start is tried in turn until one decodes. If none does,
// the error of the first attempt is returned.
func decodeJSONValue(b []byte, v any) error {
	var firstErr error
	for off := 0; off < len(b); {
		i := bytes.IndexAny(b[off:], "{[")
		if i < 0 {
			break
		}
		start := off + i
		var raw json.RawMessage
		err := json.NewDecoder(bytes.NewReader(b[start:])).Decode(&raw)
		if err == nil {
			if err = json.Unmarshal(raw, v); err == nil {
				return nil
			}
		}
		if firstErr == nil {
			firstErr = err
		}
		off = start + 1
	}
	if firstErr != nil {
		return firstErr
	}
	return json.NewDecoder(bytes.NewReader(b)).Decode(v)
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

// NetworkRule is a single host-level allow rule that sbx currently has
// scoped to a sandbox, with enough information to remove it precisely.
// ID is empty when the rule bundles more than one resource under a single
// rule ID (as kit-provided policies sometimes do) and therefore cannot be
// narrowed to a single host by ID.
type NetworkRule struct {
	ID   string
	Host string
}

// ListScopedNetworkRules returns the network allow rules that sbx currently
// has scoped specifically to the given sandbox (scope "sandbox:<sandbox>",
// decision "allow", editable).
//
// Global/kit-provided defaults (scope "global", applies_to "all", e.g. the
// default package-manager/cloud-infra bundles) are deliberately excluded:
// they apply to every sandbox on the host and are not something a single
// project's policy.yaml should own or ever attempt to remove. Mixing them
// into the diff used to reconcile would make "sync up" try to
// revoke hundreds of unrelated default domains the moment they are absent
// from a project's small network_allowlist.
func (c *Client) ListScopedNetworkRules(sandbox string) ([]NetworkRule, error) {
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
	if err := decodeJSONValue(out, &resp); err != nil {
		return nil, fmt.Errorf("parse sbx policy ls --json output: %w\noutput: %s", err, string(out))
	}

	wantScope := "sandbox:" + sandbox
	var rules []NetworkRule
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
			rules = append(rules, NetworkRule{ID: id, Host: host})
		}
	}
	return rules, nil
}

// ListNetworkRules returns the network allowlist entries that sbx currently
// has scoped to the given sandbox. See ListScopedNetworkRules for exactly
// what is (and isn't) included.
func (c *Client) ListNetworkRules(sandbox string) ([]string, error) {
	rules, err := c.ListScopedNetworkRules(sandbox)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(rules))
	for _, r := range rules {
		hosts = append(hosts, r.Host)
	}
	return hosts, nil
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
// ID, as returned by ListNetworkRules/ListScopedNetworkRules. This deletes
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
	if err := decodeJSONValue(out, &mappings); err != nil {
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
