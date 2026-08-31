package project

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentifyFallback(t *testing.T) {
	tmp := t.TempDir()
	id, err := Identify(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(id.Root, filepath.Base(tmp)) {
		t.Fatalf("unexpected root: %s", id.Root)
	}
	if id.Name != filepath.Base(tmp) {
		t.Fatalf("unexpected name: %s", id.Name)
	}
}

func TestStateKey(t *testing.T) {
	id := Identity{Root: "/home/user/projects/foo", Name: "foo"}
	key := id.StateKey()
	if !strings.HasPrefix(key, "foo-") {
		t.Fatalf("expected key to start with 'foo-', got: %s", key)
	}
}

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"git@github.com:daliendev/sbx-policy.git", "github.com/daliendev/sbx-policy.git"},
		{"https://github.com/daliendev/sbx-policy.git", "github.com/daliendev/sbx-policy.git"},
		{"ssh://git@github.com/daliendev/sbx-policy.git", "github.com/daliendev/sbx-policy.git"},
	}
	for _, tt := range tests {
		got := normalizeGitURL(tt.input)
		if got != tt.expected {
			t.Fatalf("normalizeGitURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
