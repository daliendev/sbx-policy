package policy

import (
	"strings"
	"testing"

	"github.com/daliendev/sbx-policy/internal/config"
)

func TestValidateVersion(t *testing.T) {
	p := config.Policy{Version: 2, NetworkAllowlist: []string{}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "unsupported policy version") {
		t.Fatalf("expected version error, got: %v", err)
	}
}

func TestValidateEmptyEntry(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{"github.com", ""}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty entry error, got: %v", err)
	}
}

func TestValidateComma(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{"evil.com,good.com"}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "comma") {
		t.Fatalf("expected comma error, got: %v", err)
	}
}

func TestValidateWhitespace(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{"evil.com "}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("expected whitespace error, got: %v", err)
	}
}

func TestValidateWildcard(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{"*.githubusercontent.com"}}
	if err := Validate(p); err != nil {
		t.Fatalf("unexpected error for wildcard: %v", err)
	}
}

func TestValidatePort(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{"api.example.com:443"}}
	if err := Validate(p); err != nil {
		t.Fatalf("unexpected error for port: %v", err)
	}
}

func TestValidateNilAllowlist(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: nil}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "must be a list") {
		t.Fatalf("expected nil list error, got: %v", err)
	}
}

func TestNormalize(t *testing.T) {
	in := []string{"b", "a", "a", "c"}
	out := Normalize(in)
	expected := []string{"a", "b", "c"}
	if len(out) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, out)
	}
	for i := range expected {
		if out[i] != expected[i] {
			t.Fatalf("expected %v, got %v", expected, out)
		}
	}
}

func TestDiff(t *testing.T) {
	old := []string{"a", "b"}
	new := []string{"b", "c"}
	d := Compare(old, new)

	if len(d.Added) != 1 || d.Added[0] != "c" {
		t.Fatalf("expected added [c], got %v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "a" {
		t.Fatalf("expected removed [a], got %v", d.Removed)
	}
	if !d.HasChanges() {
		t.Fatal("expected HasChanges=true")
	}
}

func TestDiffNoChanges(t *testing.T) {
	old := []string{"a", "b"}
	new := []string{"a", "b"}
	d := Compare(old, new)
	if d.HasChanges() {
		t.Fatal("expected HasChanges=false")
	}
}

func TestDiffFormat(t *testing.T) {
	d := Diff{Added: []string{"x"}, Removed: []string{"y"}}
	f := d.Format()
	if !strings.Contains(f, "+ x") {
		t.Fatalf("expected + x in diff, got:\n%s", f)
	}
	if !strings.Contains(f, "- y") {
		t.Fatalf("expected - y in diff, got:\n%s", f)
	}
}

func TestValidatePortMappingOK(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{}, Ports: []string{"8080:3000", "3000"}}
	if err := Validate(p); err != nil {
		t.Fatalf("unexpected error for valid ports: %v", err)
	}
}

func TestValidatePortMappingWhitespace(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{}, Ports: []string{"8080 :3000"}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("expected whitespace error for ports, got: %v", err)
	}
}

func TestValidatePortMappingTooManyColons(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{}, Ports: []string{"8080:3000:4000"}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "more than one colon") {
		t.Fatalf("expected colon error for ports, got: %v", err)
	}
}

func TestValidatePortMappingNonNumeric(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{}, Ports: []string{"abc:3000"}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "non-numeric") {
		t.Fatalf("expected non-numeric error for ports, got: %v", err)
	}
}

func TestValidatePortMappingOutOfRange(t *testing.T) {
	p := config.Policy{Version: 1, NetworkAllowlist: []string{}, Ports: []string{"99999:3000"}}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected out of range error for ports, got: %v", err)
	}
}

func TestValidateRejectsControlCharacters(t *testing.T) {
	for _, entry := range []string{
		"evil.com\x1b[2A\x1b[2Kgithub.com", // terminal escape sequence
		"evil.com\x07",                     // bell
		"evil.com\x7f",                     // DEL
		"evil.com\u009b2K",                 // C1 CSI
		"github.com‮gpj.exe",               // bidi override
	} {
		if err := ValidateNetworkEntry(entry); err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("ValidateNetworkEntry(%q) = %v, want control character error", entry, err)
		}
		if err := ValidateSandboxName(entry); err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("ValidateSandboxName(%q) = %v, want control character error", entry, err)
		}
	}
	if err := ValidatePortMapping("80\x1b[2K:80"); err == nil {
		t.Error("ValidatePortMapping accepted an escape sequence")
	}
}

func TestValidateRejectsLeadingDash(t *testing.T) {
	for _, entry := range []string{"-h", "--sandbox=other", "--global"} {
		if err := ValidateNetworkEntry(entry); err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("ValidateNetworkEntry(%q) = %v, want leading dash error", entry, err)
		}
		if err := ValidateSandboxName(entry); err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("ValidateSandboxName(%q) = %v, want leading dash error", entry, err)
		}
	}
	// A dash elsewhere is fine (hyphenated hosts and sandbox names).
	for _, ok := range []string{"my-host.example.com", "a-b"} {
		if err := ValidateNetworkEntry(ok); err != nil {
			t.Errorf("ValidateNetworkEntry(%q) = %v", ok, err)
		}
		if err := ValidateSandboxName(ok); err != nil {
			t.Errorf("ValidateSandboxName(%q) = %v", ok, err)
		}
	}
}

func TestValidatePolicyRejectsHostileFile(t *testing.T) {
	p := config.Policy{Version: 1, Sandbox: "--global", NetworkAllowlist: []string{}}
	if err := Validate(p); err == nil {
		t.Error("Validate accepted a sandbox named --global")
	}
	p = config.Policy{Version: 1, NetworkAllowlist: []string{"ok.com", "--sandbox=other"}}
	if err := Validate(p); err == nil {
		t.Error("Validate accepted a flag-like network entry")
	}
}
