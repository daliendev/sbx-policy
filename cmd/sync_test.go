package cmd

import (
	"bufio"
	"strings"
	"testing"

	"github.com/daliendev/sbx-policy/internal/reconcile"
	"github.com/daliendev/sbx-policy/internal/sbx"
)

// An empty answer (Enter, or EOF) must never approve a first sync that
// removes something from sbx, while an additions-only first sync keeps its
// default-yes.
func TestConfirmSyncFirstSyncDefaults(t *testing.T) {
	if !isStdinCharDevice() {
		t.Skip("stdin is not a character device; confirmSync would refuse to prompt")
	}
	tests := []struct {
		name string
		plan reconcile.Plan
		want bool
	}{
		{"additions only", reconcile.Plan{AddHosts: []string{"a.com"}}, true},
		{"removes a rule", reconcile.Plan{RemoveRules: []sbx.NetworkRule{{ID: "1", Host: "a.com"}}}, false},
		{"unpublishes a port", reconcile.Plan{Unpublish: []string{"49152:3000"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := stdin
			t.Cleanup(func() { stdin = old })
			stdin = bufio.NewReader(strings.NewReader("\n"))

			got, err := confirmSync(tt.plan, askUser, reconcile.Desired{}, nil, nil, "sb", nil, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("confirmSync = %v, want %v", got, tt.want)
			}
		})
	}
}
