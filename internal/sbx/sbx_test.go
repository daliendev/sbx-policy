package sbx

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestRealRunnerSeparatesStdoutStderr guards against a regression to
// cmd.CombinedOutput(), which merges stdout and stderr into one buffer. sbx
// sometimes writes an unrelated banner to stderr after a JSON command
// finishes; if the two streams are merged, that banner gets appended right
// after the JSON on stdout and breaks json.Unmarshal downstream (see
// listScopedNetworkRules/ListPorts, which parse Run's output as JSON).
func TestRealRunnerSeparatesStdoutStderr(t *testing.T) {
	r := &RealRunner{}
	out, err := r.Run("sh", "-c", `echo '{"ok":true}'; echo '╭ update available ╮' >&2`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != `{"ok":true}` {
		t.Fatalf("expected stdout only (no stderr banner), got: %q", got)
	}
}

// TestDecodeJSONValueIgnoresBanner guards against a regression where sbx
// writes its update-notice banner to stdout itself (not just stderr, which
// TestRealRunnerSeparatesStdoutStderr already covers), either before or
// after the JSON it prints for a --json command. json.Unmarshal rejects
// that outright; decodeJSONValue must tolerate it on either side.
func TestDecodeJSONValueIgnoresBanner(t *testing.T) {
	cases := map[string]string{
		"trailing banner": "{\"rules\":[]}\n╭ update available ╮\n",
		"leading banner":  "╭ update available ╮\n{\"rules\":[]}\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var resp policyLsResponse
			if err := decodeJSONValue([]byte(raw), &resp); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Rules) != 0 {
				t.Fatalf("expected empty rules, got: %v", resp.Rules)
			}
		})
	}
}

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

// TestListNetworkRulesToleratesTrailingBanner reproduces the reported bug:
// "sbx policy ls --json" succeeds but sbx appends an update-notice banner
// (box-drawing characters) to stdout right after the JSON, which previously
// made json.Unmarshal fail with "invalid character '╭' after top-level
// value" and made sync fall back to defensively re-adding rules that were
// already present.
func TestListNetworkRulesToleratesTrailingBanner(t *testing.T) {
	lsJSON := networkRulesJSON("my-sandbox", map[string]string{"laravel.com": "rule-laravel"})
	mock := &scriptedRunner{lsJSON: lsJSON + "\n╭──────────────────────╮\n│ update available     │\n╰──────────────────────╯\n"}
	client := &Client{Runner: mock}

	rules, err := client.ListScopedNetworkRules("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 || rules[0] != (NetworkRule{ID: "rule-laravel", Host: "laravel.com"}) {
		t.Fatalf("got rules %v", rules)
	}
}

// A rule bundling more than one resource under a single ID (as kit-managed
// policies can) must come back without an ID, so callers never remove it by
// ID and take every resource in the bundle with it.
func TestListScopedNetworkRulesBundledRuleHasNoID(t *testing.T) {
	mock := &scriptedRunner{lsJSON: `{"rules":[{"id":"bundle","name":"bundle","policy_id":"p","scope":"sandbox:my-sandbox","applies_to":"sandbox:my-sandbox","resource_type":"network","decision":"allow","resources":["a.com","b.com"],"origin":"scoped","layer":"local","status":"active","editable":true,"sandbox_id":"my-sandbox"}]}`}
	client := &Client{Runner: mock}

	rules, err := client.ListScopedNetworkRules("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []NetworkRule{{Host: "a.com"}, {Host: "b.com"}}
	if len(rules) != 2 || rules[0] != want[0] || rules[1] != want[1] {
		t.Fatalf("got %v, want %v", rules, want)
	}
}

func TestAddNetworkRulesBatchesAndScopesToSandbox(t *testing.T) {
	mock := &scriptedRunner{}
	client := &Client{Runner: mock}

	if err := client.AddNetworkRules([]string{"new.com", "other.com"}, "my-sandbox"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"sbx", "policy", "allow", "network", "--sandbox", "my-sandbox", "new.com,other.com"}
	if len(mock.calls) != 1 || !reflect.DeepEqual(mock.calls[0], want) {
		t.Fatalf("got calls %v, want [%v]", mock.calls, want)
	}
}

func TestAddNetworkRulesNoHostsIsNoop(t *testing.T) {
	mock := &scriptedRunner{}
	client := &Client{Runner: mock}

	if err := client.AddNetworkRules(nil, "my-sandbox"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("expected no sbx call, got %v", mock.calls)
	}
}

func TestPublishPort(t *testing.T) {
	mock := &scriptedRunner{}
	client := &Client{Runner: mock}

	if err := client.PublishPort("8080:3000", "my-sandbox"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"sbx", "ports", "my-sandbox", "--publish", "8080:3000"}
	if len(mock.calls) != 1 || !reflect.DeepEqual(mock.calls[0], want) {
		t.Fatalf("got calls %v, want [%v]", mock.calls, want)
	}
}

func TestPublishPortRequiresSandbox(t *testing.T) {
	client := &Client{Runner: &scriptedRunner{}}
	if err := client.PublishPort("8080:3000", ""); err == nil {
		t.Fatal("expected error when sandbox is empty")
	}
}
