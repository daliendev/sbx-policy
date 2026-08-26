package sbx

import (
	"fmt"
	"testing"
)

type mockRunner struct {
	calls [][]string
}

func (m *mockRunner) Run(name string, arg ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, arg...))
	return []byte("allow network github.com\nallow network example.com"), nil
}

func (m *mockRunner) RunInteractive(name string, arg ...string) error {
	m.calls = append(m.calls, append([]string{name}, arg...))
	return nil
}

func TestSyncNetworkPolicyIdempotent(t *testing.T) {
	mock := &mockRunner{}
	client := &Client{Runner: mock}

	// First sync
	err := client.SyncNetworkPolicy([]string{"github.com", "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second sync with same list should not add again (because mock reports them present)
	mock.calls = nil
	err = client.SyncNetworkPolicy([]string{"github.com", "example.com"})
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

	err := client.SyncNetworkPolicy([]string{"new.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if len(call) >= 4 && call[1] == "policy" && call[2] == "allow" && call[3] == "network" && call[4] == "new.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected add call for new.com, got calls: %v", mock.calls)
	}
}

func TestSyncNetworkPolicyFallbackWhenListFails(t *testing.T) {
	failRunner := &failListRunner{}
	client := &Client{Runner: failRunner}

	err := client.SyncNetworkPolicy([]string{"fallback.com"})
	if err == nil {
		t.Fatal("expected error when list fails")
	}

	found := false
	for _, call := range failRunner.calls {
		if len(call) >= 4 && call[4] == "fallback.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected defensive add for fallback.com, got calls: %v", failRunner.calls)
	}
}

type failListRunner struct {
	calls [][]string
}

func (f *failListRunner) Run(name string, arg ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, arg...))
	if len(arg) >= 2 && arg[0] == "policy" && arg[1] == "list" {
		return nil, fmt.Errorf("sbx policy list not supported")
	}
	return nil, nil
}

func (f *failListRunner) RunInteractive(name string, arg ...string) error {
	f.calls = append(f.calls, append([]string{name}, arg...))
	return nil
}
