package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindProjectRoot(t *testing.T) {
	tmp := t.TempDir()
	policyDir := filepath.Join(tmp, ".sbx")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sub := filepath.Join(tmp, "a", "b", "c")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	root, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root != tmp {
		t.Fatalf("expected root %q, got %q", tmp, root)
	}
}

func TestFindProjectRootNotFound(t *testing.T) {
	tmp := t.TempDir()
	_, err := FindProjectRoot(tmp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoadAndWrite(t *testing.T) {
	tmp := t.TempDir()
	p := Policy{
		Version:          1,
		NetworkAllowlist: []string{"github.com", "example.com"},
	}

	if err := Write(tmp, p); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := Load(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Version != 1 {
		t.Fatalf("version: expected 1, got %d", loaded.Version)
	}
	if len(loaded.NetworkAllowlist) != 2 {
		t.Fatalf("allowlist length: expected 2, got %d", len(loaded.NetworkAllowlist))
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".sbx"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".sbx", "policy.yaml"), []byte("not: valid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmp)
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}
