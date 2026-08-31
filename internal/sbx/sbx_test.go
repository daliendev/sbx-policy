package sbx

import (
	"fmt"
	"strings"
	"testing"
)

type mockRunner struct {
	calls [][]string
}

func (m *mockRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	return []byte("allow network github.com\nallow network example.com"), nil
}

func TestSyncNetworkPolicyIdempotent(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	// First sync
	err := client.SyncNetworkPolicy([]string{"github.com", "example.com"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second sync with same list should not add again (because mock reports them present)
	mock.calls = nil
	err = client.SyncNetworkPolicy([]string{"github.com", "example.com"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No AddNetworkRule calls expected because both are already present
	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "policy" && call[2] == "allow" {
			t.Fatalf("unexpected add call: %v", call)
		}
	}
}

func TestSyncNetworkPolicyAddsMissing(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	err := client.SyncNetworkPolicy([]string{"new.com"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "policy" && call[2] == "allow" && call[3] == "network" && call[4] == "new.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected add call for new.com, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyRemovesExtra(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	// current has github.com and example.com; desired only has github.com
	err := client.SyncNetworkPolicy([]string{"github.com"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 5 && call[1] == "policy" && call[2] == "deny" && call[3] == "network" && call[4] == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected remove call for example.com, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyFallbackWhenListFails(t *testing.T) {
	failRunner := &failListRunner{}
	client := &Client{Runner: failRunner}

	err := client.SyncNetworkPolicy([]string{"fallback.com"}, "")
	if err == nil {
		t.Fatal("expected error when list fails")
	}

	found := false
	for _, call := range failRunner.calls {
		if len(call) >= 5 && call[4] == "fallback.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected defensive add for fallback.com, got calls: %v", failRunner.calls)
	}
}

func TestSyncNetworkPolicyScopedToSandbox(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	err := client.SyncNetworkPolicy([]string{"scoped.com"}, "my-sandbox")
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

type failListRunner struct {
	calls [][]string
}

func (f *failListRunner) Run(name string, arg ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, arg...))
	if len(arg) >= 2 && arg[0] == "policy" && arg[1] == "ls" {
		return nil, fmt.Errorf("sbx policy ls not supported")
	}
	return nil, nil
}

type mockLsRunner struct {
	calls [][]string
}

func (m *mockLsRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	return []byte("SANDBOX         AGENT   STATUS   PORTS                    WORKSPACE\nmy-sandbox      claude  running  127.0.0.1:8080->3000/tcp /home/user/proj\n"), nil
}

func TestListPorts(t *testing.T) {
	mock := &mockLsRunner{}
	client := &Client{Runner: mock}

	ports, err := client.ListPorts("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != "8080:3000" {
		t.Fatalf("expected [8080:3000], got: %v", ports)
	}
}

func TestListPortsExactMatch(t *testing.T) {
	mock := &mockRunnerWithLsOutput{
		output: "SANDBOX         AGENT   STATUS   PORTS                    WORKSPACE\nmy              claude  running  127.0.0.1:8080->3000/tcp /home/user/proj\nmy-sandbox      claude  running  127.0.0.1:9090->4000/tcp /home/user/proj2\n",
	}
	client := &Client{Runner: mock}

	ports, err := client.ListPorts("my")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != "8080:3000" {
		t.Fatalf("expected [8080:3000], got: %v", ports)
	}
}

func TestSyncPortsIdempotent(t *testing.T) {
	mock := &mockLsRunner{}
	client := &Client{Runner: mock}

	err := client.SyncPorts([]string{"8080:3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second sync should not publish again
	mock.calls = nil
	err = client.SyncPorts([]string{"8080:3000"}, "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, call := range mock.calls {
		if len(call) >= 3 && call[1] == "ports" {
			t.Fatalf("unexpected ports call: %v", call)
		}
	}
}

type mockLsRunnerWithBarePort struct {
	calls      [][]string
	callCount  int
	beforePort string
	afterPort  string
}

func (m *mockLsRunnerWithBarePort) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	if len(arg) >= 1 && arg[0] == "ls" {
		m.callCount++
		if m.callCount == 1 {
			return []byte("SANDBOX         AGENT   STATUS   PORTS                    WORKSPACE\nmy-sandbox      claude  running  " + m.beforePort + " /home/user/proj\n"), nil
		}
		return []byte("SANDBOX         AGENT   STATUS   PORTS                    WORKSPACE\nmy-sandbox      claude  running  " + m.afterPort + " /home/user/proj\n"), nil
	}
	if len(arg) >= 2 && arg[0] == "policy" && arg[1] == "ls" {
		return []byte(""), nil
	}
	return []byte(""), nil
}

func TestSyncPortsBarePortIdempotent(t *testing.T) {
	// First call: no ports present. Second call: port was published with random host port.
	mock := &mockLsRunnerWithBarePort{
		beforePort: "",
		afterPort:  "127.0.0.1:49152->3000/tcp",
	}
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
		if len(call) >= 3 && call[1] == "ports" {
			t.Fatalf("unexpected ports call on second sync: %v", call)
		}
	}
}

func TestSyncPortsAddsMissing(t *testing.T) {
	mock := &mockLsRunner{}
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
	mock := &mockLsRunner{}
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

type mockRunnerWithLsOutput struct {
	calls  [][]string
	output string
}

func (m *mockRunnerWithLsOutput) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	if len(arg) >= 1 && arg[0] == "ls" {
		return []byte(m.output), nil
	}
	if len(arg) >= 2 && arg[0] == "policy" && arg[1] == "ls" {
		return []byte(""), nil
	}
	return []byte(""), nil
}

func TestRemoveNetworkRuleScoped(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	err := client.RemoveNetworkRule("example.com", "my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 7 && call[1] == "policy" && call[2] == "deny" && call[3] == "network" &&
			call[4] == "--sandbox" && call[5] == "my-sandbox" && call[6] == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected scoped deny call, got calls: %v", mock.calls)
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
