package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrPolicyNotFound is returned when FindProjectRoot cannot locate a policy file.
var ErrPolicyNotFound = errors.New("policy file not found")

const PolicyFileName = ".sbx/policy.yaml"

type Policy struct {
	Version          int      `yaml:"version"`
	Sandbox          string   `yaml:"sandbox,omitempty"`
	NetworkAllowlist []string `yaml:"network_allowlist"`
	Ports            []string `yaml:"ports,omitempty"`
}

// DefaultPolicy returns the initial policy content.
func DefaultPolicy() Policy {
	return Policy{
		Version:          1,
		NetworkAllowlist: []string{},
		Ports:            []string{},
	}
}

// FindProjectRoot walks upward from startDir until it finds a directory
// containing .sbx/policy.yaml.
func FindProjectRoot(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, PolicyFileName)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("%w: no %s found", ErrPolicyNotFound, PolicyFileName)
}

func Load(projectRoot string) (Policy, error) {
	path := filepath.Join(projectRoot, PolicyFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy file: %w", err)
	}

	return p, nil
}

// Write saves p to the project's policy file. When the file already exists
// its YAML tree is updated in place rather than regenerated, so comments,
// key order, unknown keys and indentation survive edits made by the CLI
// (the file is meant to be hand-edited and versioned).
func Write(projectRoot string, p Policy) error {
	path := filepath.Join(projectRoot, PolicyFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read policy file: %w", err)
	}
	data, err := render(existing, p)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}

	return nil
}

// render encodes p, merging it into existing (the current file content, if
// any) so that whatever p does not model is kept as-is.
func render(existing []byte, p Policy) ([]byte, error) {
	var doc yaml.Node
	if len(existing) == 0 || yaml.Unmarshal(existing, &doc) != nil ||
		doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		if err := doc.Encode(&p); err != nil {
			return nil, fmt.Errorf("marshal policy: %w", err)
		}
	} else {
		mergePolicy(doc.Content[0], p)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(detectIndent(existing))
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return buf.Bytes(), nil
}

// policyKeys lists the keys Policy models, in the order a fresh file uses.
// New keys are inserted after the nearest preceding key already present.
var policyKeys = []string{"version", "sandbox", "network_allowlist", "ports"}

// mergePolicy sets the keys Policy models on the mapping node m, leaving
// every other key (and all comments) untouched. Like the struct tags, sandbox
// and ports are dropped when empty while network_allowlist is always kept.
func mergePolicy(m *yaml.Node, p Policy) {
	setScalar(m, "version", strconv.Itoa(p.Version), "!!int", true)
	setScalar(m, "sandbox", p.Sandbox, "!!str", p.Sandbox != "")
	setSequence(m, "network_allowlist", p.NetworkAllowlist, true)
	setSequence(m, "ports", p.Ports, len(p.Ports) > 0)
}

// mapValue returns the position of key's value node in the mapping m, or -1.
func mapValue(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i + 1
		}
	}
	return -1
}

// setEntry makes key point at value in m: it replaces the value in place
// (keeping the key's comments), inserts it at its canonical position, or
// removes the key when value is nil.
func setEntry(m *yaml.Node, key string, value *yaml.Node) {
	if i := mapValue(m, key); i >= 0 {
		if value == nil {
			m.Content = append(m.Content[:i-1], m.Content[i+1:]...)
		} else {
			m.Content[i] = value
		}
		return
	}
	if value == nil {
		return
	}

	at := 0
	for _, k := range policyKeys {
		if k == key {
			break
		}
		if i := mapValue(m, k); i >= 0 {
			at = i + 1
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	m.Content = append(m.Content[:at], append([]*yaml.Node{keyNode, value}, m.Content[at:]...)...)
}

// setScalar sets key to a scalar value, reusing the existing node so its
// comments and quoting style stay; keep=false removes the key.
func setScalar(m *yaml.Node, key, value, tag string, keep bool) {
	if !keep {
		setEntry(m, key, nil)
		return
	}
	if i := mapValue(m, key); i >= 0 && m.Content[i].Kind == yaml.ScalarNode {
		m.Content[i].Value = value
		m.Content[i].Tag = tag
		return
	}
	setEntry(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
}

// setSequence sets key to a list of strings. Items that were already in the
// list keep their node, so their comments survive; keep=false removes the key.
func setSequence(m *yaml.Node, key string, entries []string, keep bool) {
	if !keep {
		setEntry(m, key, nil)
		return
	}

	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	old := map[string][]*yaml.Node{}
	if i := mapValue(m, key); i >= 0 && m.Content[i].Kind == yaml.SequenceNode {
		prev := m.Content[i]
		seq.HeadComment, seq.LineComment, seq.FootComment = prev.HeadComment, prev.LineComment, prev.FootComment
		for _, item := range prev.Content {
			old[item.Value] = append(old[item.Value], item)
		}
	}
	for _, e := range entries {
		if nodes := old[e]; len(nodes) > 0 {
			seq.Content = append(seq.Content, nodes[0])
			old[e] = nodes[1:]
			continue
		}
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e})
	}
	if len(seq.Content) == 0 {
		seq.Style = yaml.FlowStyle
	}
	setEntry(m, key, seq)
}

// detectIndent returns the indentation width used by data (the leading
// spaces of its first indented line), defaulting to 2, so rewriting the file
// does not reflow it.
func detectIndent(data []byte) int {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if n := len(line) - len(trimmed); n >= 2 && n <= 9 {
			return n
		}
	}
	return 2
}
