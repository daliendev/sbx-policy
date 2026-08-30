package state

import (
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	mgr := &Manager{Dir: dir}
	key := "test-project"

	s := ProjectState{Allowlist: []string{"a", "b"}}
	if err := mgr.Save(key, s); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, found, err := mgr.Load(key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if len(loaded.Allowlist) != 2 || loaded.Allowlist[0] != "a" {
		t.Fatalf("unexpected loaded state: %v", loaded.Allowlist)
	}
}

func TestLoadNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := &Manager{Dir: dir}

	_, found, err := mgr.Load("missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false")
	}
}

func TestFilePath(t *testing.T) {
	mgr := &Manager{Dir: "/state"}
	p := mgr.filePath("mykey")
	expected := filepath.Join("/state", "mykey.json")
	if p != expected {
		t.Fatalf("expected %q, got %q", expected, p)
	}
}
