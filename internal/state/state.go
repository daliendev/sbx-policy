package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manager handles persistence of remembered policy state.
type Manager struct {
	Dir string
}

// ProjectState is the stored state for a single project.
type ProjectState struct {
	Allowlist []string `json:"allowlist"`
	Sandbox   string   `json:"sandbox,omitempty"`
	Ports     []string `json:"ports,omitempty"`
}

func DefaultDir() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			configDir = filepath.Join(home, ".config")
		} else {
			configDir = os.TempDir()
		}
	}
	return filepath.Join(configDir, "sbx-policy")
}

func NewManager() *Manager {
	return &Manager{Dir: DefaultDir()}
}

// Load reads the remembered state for the given project key.
func (m *Manager) Load(key string) (ProjectState, bool, error) {
	path := m.filePath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProjectState{}, false, nil
		}
		return ProjectState{}, false, fmt.Errorf("read state: %w", err)
	}

	var s ProjectState
	if err := json.Unmarshal(data, &s); err != nil {
		return ProjectState{}, false, fmt.Errorf("parse state: %w", err)
	}

	return s, true, nil
}

func (m *Manager) Save(key string, s ProjectState) error {
	if err := os.MkdirAll(m.Dir, 0755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	path := m.filePath(key)
	data, err := json.MarshalIndent(&s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}

	return nil
}

func (m *Manager) filePath(key string) string {
	return filepath.Join(m.Dir, fmt.Sprintf("%s.json", key))
}
