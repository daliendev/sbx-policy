package sbx

import (
	"fmt"
	"strings"
	"testing"
)

// mockRunner is a dumb runner whose response content is irrelevant to the
// call under test (only the recorded calls matter).
type mockRunner struct {
	calls [][]string
}

func (m *mockRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	return []byte(""), nil
}

// scriptedRunner returns a scripted JSON response for "sbx policy ls ..."
// calls (or a scripted error), and empty output for everything else. Use it
// for any test that exercises listScopedNetworkRules/SyncNetworkPolicy.
type scriptedRunner struct {
	calls  [][]string
	lsJSON string
	lsErr  error
}

func (m *scriptedRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	if len(arg) >= 2 && arg[0] == "policy" && arg[1] == "ls" {
		if m.lsErr != nil {
			return nil, m.lsErr
		}
		return []byte(m.lsJSON), nil
	}
	return []byte(""), nil
}

// networkRulesJSON builds a "sbx policy ls --json" response with one
// scoped, editable, single-resource allow rule per host/ruleID pair.
func networkRulesJSON(sandbox string, hostToRuleID map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"rules":[`)
	first := true
	for host, id := range hostToRuleID {
		if !first {
			b.WriteString(",")
		}
		first = false
		fmt.Fprintf(&b, `{"id":%q,"name":%q,"policy_id":"p","scope":"sandbox:%s","applies_to":"sandbox:%s","resource_type":"network","decision":"allow","resources":[%q],"origin":"scoped","layer":"local","status":"active","editable":true,"sandbox_id":%q}`,
			id, id, sandbox, sandbox, host, sandbox)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestSyncNetworkPolicyIdempotent(t *testing.T) {
	mock := &scriptedRunner{lsJSON: networkRulesJSON("my-sandbox", map[string]string{
		"github.com":  "rule-github",
		"example.com": "rule-example",
	})}
	client := &Client{Runner: mock}

	// First sync
	_, err := client.SyncNetworkPolicy([]string{"github.com", "example.com"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second sync with same list should not add or remove anything, because
	// both hosts are already present with the same scope.
	mock.calls = nil
	_, err = client.SyncNetworkPolicy([]string{"github.com", "example.com"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "policy" && (call[2] == "allow" || call[2] == "rm") {
			t.Fatalf("unexpected mutating call: %v", call)
		}
	}
}

func TestSyncNetworkPolicyAddsMissing(t *testing.T) {
	mock := &scriptedRunner{lsJSON: networkRulesJSON("my-sandbox", nil)}
	client := &Client{Runner: mock}

	_, err := client.SyncNetworkPolicy([]string{"new.com", "other.com"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 7 && call[1] == "policy" && call[2] == "allow" && call[3] == "network" &&
			call[4] == "--sandbox" && call[5] == "my-sandbox" && call[6] == "new.com,other.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected batch add call for missing hosts, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyRemovesExtra(t *testing.T) {
	mock := &scriptedRunner{lsJSON: networkRulesJSON("my-sandbox", map[string]string{
		"github.com":  "rule-github",
		"example.com": "rule-example",
	})}
	client := &Client{Runner: mock}

	// current has github.com and example.com; desired only has github.com
	_, err := client.SyncNetworkPolicy([]string{"github.com"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 7 && call[1] == "policy" && call[2] == "rm" && call[3] == "network" &&
			call[4] == "--id" && call[5] == "rule-example" && call[6] == "--sandbox" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'policy rm network --id rule-example --sandbox my-sandbox' call, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyDoesNotRemoveBundledRule(t *testing.T) {
	// A rule bundling more than one resource under a single ID (as
	// kit-managed policies can) must never be removed by ID, since that
	// would take every resource in the bundle with it.
	mock := &scriptedRunner{lsJSON: `{"rules":[{"id":"bundle","name":"bundle","policy_id":"p","scope":"sandbox:my-sandbox","applies_to":"sandbox:my-sandbox","resource_type":"network","decision":"allow","resources":["a.com","b.com"],"origin":"scoped","layer":"local","status":"active","editable":true,"sandbox_id":"my-sandbox"}]}`}
	client := &Client{Runner: mock}

	result, err := client.SyncNetworkPolicy([]string{}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "policy" && call[2] == "rm" {
			t.Fatalf("must not remove a bundled multi-resource rule by ID, got call: %v", call)
		}
	}

	// The caller needs to know these hosts couldn't be removed, since they
	// are silently left allowed in sbx rather than being cleaned up.
	wantSkipped := map[string]bool{"a.com": true, "b.com": true}
	if len(result.SkippedRemovals) != len(wantSkipped) {
		t.Fatalf("expected SkippedRemovals %v, got: %v", wantSkipped, result.SkippedRemovals)
	}
	for _, h := range result.SkippedRemovals {
		if !wantSkipped[h] {
			t.Fatalf("unexpected host in SkippedRemovals: %s (got: %v)", h, result.SkippedRemovals)
		}
	}
}

func TestSyncNetworkPolicyFallbackWhenListFails(t *testing.T) {
	mock := &scriptedRunner{lsErr: fmt.Errorf("sbx policy ls not supported")}
	client := &Client{Runner: mock}

	desired := []string{"fallback.com", "second.example"}
	_, err := client.SyncNetworkPolicy(desired, "my-sandbox")
	if err == nil {
		t.Fatal("expected error when list fails")
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 7 && call[1] == "policy" && call[2] == "allow" && call[3] == "network" &&
			call[4] == "--sandbox" && call[5] == "my-sandbox" && call[6] == "fallback.com,second.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected defensive batch add for desired hosts, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyScopedToSandbox(t *testing.T) {
	mock := &scriptedRunner{lsJSON: networkRulesJSON("my-sandbox", nil)}
	client := &Client{Runner: mock}

	_, err := client.SyncNetworkPolicy([]string{"scoped.com"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 7 && call[1] == "policy" && call[2] == "allow" && call[3] == "network" && call[4] == "--sandbox" && call[5] == "my-sandbox" && call[6] == "scoped.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected scoped add call for scoped.com, got calls: %v", mock.calls)
	}
}

// TestListNetworkRulesNeverUsesSandboxFlag ensures the workaround remains:
// sbx CLI rejects --sandbox on "policy ls" (the sandbox is a positional arg).
func TestListNetworkRulesNeverUsesSandboxFlag(t *testing.T) {
	mock := &scriptedRunner{lsJSON: networkRulesJSON("my-sandbox", nil)}
	client := &Client{Runner: mock}

	_, err := client.ListNetworkRules("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "policy" && call[2] == "ls" {
			for _, token := range call[3:] {
				if token == "--sandbox" {
					t.Fatalf("sbx policy ls must not include --sandbox, got call: %v", call)
				}
			}
			if len(call) < 4 || call[3] != "my-sandbox" {
				t.Fatalf("sbx policy ls must pass the sandbox as a positional arg, got call: %v", call)
			}
		}
	}
}

// TestListNetworkRulesExcludesGlobalDefaults ensures kit-provided defaults
// shared across every sandbox (scope "global", applies_to "all") never leak
// into a single project's allowlist.
func TestListNetworkRulesExcludesGlobalDefaults(t *testing.T) {
	mock := &scriptedRunner{lsJSON: `{"rules":[
		{"id":"default-package-managers","name":"default-package-managers","policy_id":"local-policy","scope":"global","applies_to":"all","resource_type":"network","decision":"allow","resources":["registry.npmjs.org:443","pypi.org:443"],"origin":"local","layer":"local","status":"active","editable":true},
		{"id":"rule-scoped","name":"rule-scoped","policy_id":"p","scope":"sandbox:my-sandbox","applies_to":"sandbox:my-sandbox","resource_type":"network","decision":"allow","resources":["scoped.example"],"origin":"scoped","layer":"local","status":"active","editable":true,"sandbox_id":"my-sandbox"}
	]}`}
	client := &Client{Runner: mock}

	hosts, err := client.ListNetworkRules("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "scoped.example" {
		t.Fatalf("expected only the sandbox-scoped host, got: %v", hosts)
	}
}

// TestListNetworkRulesExcludesDenyAndNonEditable ensures deny rules and
// non-editable (e.g. kit-managed) rules are never surfaced as part of the
// allowlist sbx-policy manages.
func TestListNetworkRulesExcludesDenyAndNonEditable(t *testing.T) {
	mock := &scriptedRunner{lsJSON: `{"rules":[
		{"id":"deny-rule","name":"deny-rule","policy_id":"p","scope":"sandbox:my-sandbox","applies_to":"sandbox:my-sandbox","resource_type":"network","decision":"deny","resources":["sandbox:my-sandbox"],"origin":"scoped","layer":"local","status":"active","editable":true,"sandbox_id":"my-sandbox"},
		{"id":"kit-rule","name":"kit:my-sandbox","policy_id":"p2","scope":"sandbox:my-sandbox","applies_to":"sandbox:my-sandbox","resource_type":"network","decision":"allow","resources":["kit-managed.example"],"origin":"scoped","layer":"local","status":"active","editable":false,"sandbox_id":"my-sandbox"}
	]}`}
	client := &Client{Runner: mock}

	hosts, err := client.ListNetworkRules("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected no hosts (deny + non-editable filtered out), got: %v", hosts)
	}
}

func TestListNetworkRulesRequiresSandbox(t *testing.T) {
	client := NewClient()
	_, err := client.ListNetworkRules("")
	if err == nil {
		t.Fatal("expected error when sandbox is empty")
	}
	if !strings.Contains(err.Error(), "sandbox name is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// portsScriptedRunner returns a scripted JSON response for "sbx ports
// <sandbox> --json" calls (or a scripted error), and empty output for
// --publish/--unpublish mutations, which don't parse their output.
type portsScriptedRunner struct {
	calls     [][]string
	portsJSON string
	portsErr  error
}

func (m *portsScriptedRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	for _, a := range arg {
		if a == "--json" {
			if m.portsErr != nil {
				return nil, m.portsErr
			}
			return []byte(m.portsJSON), nil
		}
	}
	return []byte(""), nil
}

// dualStackPortsJSON builds a "sbx ports --json" response with a
// 127.0.0.1 + ::1 tcp entry for each hostPort:sandboxPort pair, mirroring
// how a single "--publish" call binds both IP families by default.
func dualStackPortsJSON(mappings ...[2]int) string {
	var b strings.Builder
	b.WriteString("[")
	first := true
	for _, m := range mappings {
		for _, ip := range []string{"127.0.0.1", "::1"} {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, `{"host_ip":%q,"host_port":%d,"sandbox_port":%d,"protocol":"tcp"}`, ip, m[0], m[1])
		}
	}
	b.WriteString("]")
	return b.String()
}

func TestListPorts(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: dualStackPortsJSON([2]int{8080, 3000})}
	client := &Client{Runner: mock}

	ports, err := client.ListPorts("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != "8080:3000" {
		t.Fatalf("expected [8080:3000], got: %v", ports)
	}
}

// TestListPortsCollapsesDualStack ensures a single publish bound on both
// 127.0.0.1 and ::1 (sbx's default) is reported once, not twice — otherwise
// SyncPorts could issue a redundant (or failing) second --unpublish call.
func TestListPortsCollapsesDualStack(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: `[{"host_ip":"127.0.0.1","host_port":8080,"sandbox_port":8000,"protocol":"tcp"},{"host_ip":"::1","host_port":8080,"sandbox_port":8000,"protocol":"tcp"}]`}
	client := &Client{Runner: mock}

	ports, err := client.ListPorts("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != "8080:8000" {
		t.Fatalf("expected a single deduplicated [8080:8000], got: %v", ports)
	}
}

// TestListPortsPassesSandboxPositionally mirrors the same requirement as
// "sbx policy ls": the sandbox is a positional argument, not a flag.
func TestListPortsPassesSandboxPositionally(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: "[]"}
	client := &Client{Runner: mock}

	if _, err := client.ListPorts("my-sandbox"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "ports" && call[2] == "my-sandbox" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'sbx ports my-sandbox ...', got calls: %v", mock.calls)
	}
}

func TestListPortsRequiresSandbox(t *testing.T) {
	client := NewClient()
	_, err := client.ListPorts("")
	if err == nil {
		t.Fatal("expected error when sandbox is empty")
	}
	if !strings.Contains(err.Error(), "sandbox name is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSyncPortsIdempotent(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: dualStackPortsJSON([2]int{8080, 3000})}
	client := &Client{Runner: mock}

	err := client.SyncPorts([]string{"8080:3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second sync should not publish/unpublish again (a listing call is
	// still expected and fine).
	mock.calls = nil
	err = client.SyncPorts([]string{"8080:3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, call := range mock.calls {
		if len(call) >= 4 && call[1] == "ports" && (call[3] == "--publish" || call[3] == "--unpublish") {
			t.Fatalf("unexpected mutating ports call: %v", call)
		}
	}
}

// portsScriptedRunnerSequence returns one scripted "sbx ports --json"
// response per successive listing call (holding the last one steady once
// exhausted) — for tests where sbx's own visible state changes between an
// initial sync and a follow-up idempotency check.
type portsScriptedRunnerSequence struct {
	calls     [][]string
	responses []string
	listCount int
}

func (m *portsScriptedRunnerSequence) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	for _, a := range arg {
		if a == "--json" {
			idx := m.listCount
			if idx >= len(m.responses) {
				idx = len(m.responses) - 1
			}
			m.listCount++
			return []byte(m.responses[idx]), nil
		}
	}
	return []byte(""), nil
}

func TestSyncPortsBarePortIdempotent(t *testing.T) {
	// First sync: no ports present. Second sync: the port was published
	// with a random ephemeral host port.
	mock := &portsScriptedRunnerSequence{responses: []string{
		"[]",
		dualStackPortsJSON([2]int{49152, 3000}),
	}}
	client := &Client{Runner: mock}

	// First sync with bare port
	err := client.SyncPorts([]string{"3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have published once with bare port
	published := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "ports" && call[3] == "--publish" && call[4] == "3000" {
			published = true
		}
	}
	if !published {
		t.Fatalf("expected publish call for 3000, got calls: %v", mock.calls)
	}

	// Second sync should not publish again because 49152:3000 satisfies bare port 3000
	mock.calls = nil
	err = client.SyncPorts([]string{"3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, call := range mock.calls {
		if len(call) >= 4 && call[1] == "ports" && (call[3] == "--publish" || call[3] == "--unpublish") {
			t.Fatalf("unexpected mutating ports call on second sync: %v", call)
		}
	}
}

func TestSyncPortsAddsMissing(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: dualStackPortsJSON([2]int{8080, 3000})}
	client := &Client{Runner: mock}

	err := client.SyncPorts([]string{"9090:4000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "ports" && call[2] == "my-sandbox" && call[3] == "--publish" && call[4] == "9090:4000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected publish call for 9090:4000, got calls: %v", mock.calls)
	}
}

func TestSyncPortsRemovesExtra(t *testing.T) {
	mock := &portsScriptedRunner{portsJSON: dualStackPortsJSON([2]int{8080, 3000})}
	client := &Client{Runner: mock}

	// current has 8080:3000; desired is empty
	err := client.SyncPorts([]string{}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "ports" && call[2] == "my-sandbox" && call[3] == "--unpublish" && call[4] == "8080:3000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unpublish call for 8080:3000, got calls: %v", mock.calls)
	}
}

func TestRemoveNetworkRuleByIDScoped(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	err := client.RemoveNetworkRuleByID("rule-example", "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if strings.Join(call, " ") == "sbx policy rm network --id rule-example --sandbox my-sandbox" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected scoped rm call, got calls: %v", mock.calls)
	}
}

func TestRemoveNetworkRuleByIDRequiresSandbox(t *testing.T) {
	client := NewClient()
	err := client.RemoveNetworkRuleByID("rule-example", "")
	if err == nil {
		t.Fatal("expected error when sandbox is empty")
	}
	if !strings.Contains(err.Error(), "sandbox name is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestUnpublishPort(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	err := client.UnpublishPort("8080:3000", "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "ports" && call[2] == "my-sandbox" &&
			call[3] == "--unpublish" && call[4] == "8080:3000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unpublish call, got calls: %v", mock.calls)
	}
}

func TestUnpublishPortRequiresSandbox(t *testing.T) {
	client := NewClient()
	err := client.UnpublishPort("8080:3000", "")
	if err == nil {
		t.Fatal("expected error when sandbox is empty")
	}
	if !strings.Contains(err.Error(), "sandbox name is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
