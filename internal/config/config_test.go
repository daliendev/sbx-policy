package config

import (
	"os"
	"path/filepath"
	"reflect"
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

// writeRaw stores content as the project's policy file.
func writeRaw(t *testing.T, root, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".sbx"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, PolicyFileName), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readRaw(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, PolicyFileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWriteFreshFile(t *testing.T) {
	tmp := t.TempDir()
	p := Policy{Version: 1, Sandbox: "box", NetworkAllowlist: []string{"github.com"}, Ports: []string{"8080:3000", "3000"}}
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := `version: 1
sandbox: box
network_allowlist:
  - github.com
ports:
  - 8080:3000
  - "3000"
`
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("fresh file:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteEmptyDefaultPolicy(t *testing.T) {
	tmp := t.TempDir()
	if err := Write(tmp, DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if got, want := readRaw(t, tmp), "version: 1\nnetwork_allowlist: []\n"; got != want {
		t.Fatalf("default policy:\n%s\nwant:\n%s", got, want)
	}
}

func TestWritePreservesCommentsAndUnknownKeys(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, `# Project sandbox policy
version: 1
sandbox: box # the dev sandbox
experimental: keep-me
network_allowlist:
  # package registries
  - registry.npmjs.org # npm
  - github.com
# ports exposed to the host
ports:
  - "8080:3000" # web
`)

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = append(p.NetworkAllowlist, "example.com")
	p.Ports = append(p.Ports, "9090:9000")
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := `# Project sandbox policy
version: 1
sandbox: box # the dev sandbox
experimental: keep-me
network_allowlist:
  # package registries
  - registry.npmjs.org # npm
  - github.com
  - example.com
# ports exposed to the host
ports:
  - "8080:3000" # web
  - 9090:9000
`
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteKeepsIndentation(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, "version: 1\nnetwork_allowlist:\n    - github.com\n")

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = append(p.NetworkAllowlist, "example.com")
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := "version: 1\nnetwork_allowlist:\n    - github.com\n    - example.com\n"
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteRemovesEntriesAndEmptyOptionalKeys(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, `version: 1
sandbox: box
network_allowlist:
  - github.com # keep
  - example.com
ports:
  - "8080:3000"
`)

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = []string{"github.com"}
	p.Ports = nil
	p.Sandbox = ""
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := "version: 1\nnetwork_allowlist:\n  - github.com # keep\n"
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteInsertsMissingKeysInCanonicalPosition(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, "version: 1\nextra: x\nnetwork_allowlist:\n  - github.com\n")

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.Sandbox = "box"
	p.Ports = []string{"3000"}
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := "version: 1\nsandbox: box\nextra: x\nnetwork_allowlist:\n  - github.com\nports:\n  - \"3000\"\n"
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteRoundTripsAndFillsEmptyList(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, "version: 1\nnetwork_allowlist: []\n")

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = []string{"github.com"}
	p.Ports = []string{"3000", "8080:3000"}
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, p) {
		t.Fatalf("round trip: got %+v, want %+v", loaded, p)
	}
}

func TestWriteKeepsFlowStyleLists(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, "version: 1\nnetwork_allowlist: [github.com]\n")

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = append(p.NetworkAllowlist, "example.com")
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	want := "version: 1\nnetwork_allowlist: [github.com, example.com]\n"
	if got := readRaw(t, tmp); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteKeepsPermissionsAndLeavesNoTempFile(t *testing.T) {
	tmp := t.TempDir()
	writeRaw(t, tmp, "version: 1\nnetwork_allowlist: []\n")
	path := filepath.Join(tmp, PolicyFileName)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	p, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkAllowlist = []string{"github.com"}
	if err := Write(tmp, p); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only policy.yaml in .sbx, got %v", entries)
	}
}
