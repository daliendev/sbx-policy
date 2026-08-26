package project

import (
	"os"
	"os/exec"
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

func TestIdentifyGit(t *testing.T) {
	tmp := t.TempDir()

	// Initialize a git repo
	if err := os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "init")
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "remote", "add", "origin", "git@github.com:opencode/sbx-policy.git")
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v\n%s", err, out)
	}

	id, err := Identify(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Name != "github.com-opencode-sbx-policy" {
		t.Fatalf("unexpected name: %s", id.Name)
	}
}
