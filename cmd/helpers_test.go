package cmd

import (
	"reflect"
	"testing"

	"github.com/daliendev/sbx-policy/internal/reconcile"
	"github.com/daliendev/sbx-policy/internal/sbx"
)

func TestSplitCommaSeparated(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "space separated args",
			args: []string{"github.com", "registry.npmjs.org"},
			want: []string{"github.com", "registry.npmjs.org"},
		},
		{
			name: "comma separated single arg",
			args: []string{"github.com,registry.npmjs.org"},
			want: []string{"github.com", "registry.npmjs.org"},
		},
		{
			name: "mix of comma and space separated args",
			args: []string{"github.com,registry.npmjs.org", "example.com"},
			want: []string{"github.com", "registry.npmjs.org", "example.com"},
		},
		{
			name: "trims whitespace around commas",
			args: []string{"github.com, registry.npmjs.org , example.com"},
			want: []string{"github.com", "registry.npmjs.org", "example.com"},
		},
		{
			name: "ignores empty entries from stray commas",
			args: []string{"github.com,,example.com", ",", ""},
			want: []string{"github.com", "example.com"},
		},
		{
			name: "empty input",
			args: []string{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCommaSeparated(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCommaSeparated(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestRemoveEntries(t *testing.T) {
	tests := []struct {
		name   string
		list   []string
		remove []string
		want   []string
	}{
		{"removes only listed entries", []string{"49969:49969", "18080:49969"}, []string{"49969:49969"}, []string{"18080:49969"}},
		{"unknown entries are ignored", []string{"8080:3000"}, []string{"9999:9999"}, []string{"8080:3000"}},
		{"removing everything yields empty", []string{"8080:3000"}, []string{"8080:3000"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := removeEntries(tt.list, tt.remove); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("removeEntries(%v, %v) = %v, want %v", tt.list, tt.remove, got, tt.want)
			}
		})
	}
}

func TestIntersectEntries(t *testing.T) {
	tests := []struct {
		name  string
		list  []string
		other []string
		want  []string
	}{
		{"keeps list order", []string{"a", "b", "c"}, []string{"c", "a"}, []string{"a", "c"}},
		{"entries outside list are ignored", []string{"8080:3000"}, []string{"9999:9999"}, nil},
		{"nil other yields nothing", []string{"8080:3000"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := intersectEntries(tt.list, tt.other); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("intersectEntries(%v, %v) = %v, want %v", tt.list, tt.other, got, tt.want)
			}
		})
	}
}

func TestApprovalNeedsPrompt(t *testing.T) {
	add := reconcile.Plan{AddHosts: []string{"a.com"}, Publish: []string{"3000"}}
	removeRule := reconcile.Plan{RemoveRules: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}}}
	unpublish := reconcile.Plan{Unpublish: []string{"7777:7000"}}
	mixed := reconcile.Plan{AddHosts: []string{"a.com"}, Unpublish: []string{"7777:7000"}}
	// Bundled hosts are reported but never removed, so they aren't a change.
	skippedOnly := reconcile.Plan{SkippedRemovals: []string{"b.com"}}

	tests := []struct {
		name string
		appr approval
		plan reconcile.Plan
		want bool
	}{
		{"empty plan never asks", askUser, reconcile.Plan{}, false},
		{"askUser asks for additions", askUser, add, true},
		{"askUser asks for removals", askUser, removeRule, true},
		{"approveAll never asks", approveAll, mixed, false},
		{"approveAdditions applies additions silently", approveAdditions, add, false},
		{"approveAdditions asks when a rule is removed", approveAdditions, removeRule, true},
		{"approveAdditions asks when a port is unpublished", approveAdditions, unpublish, true},
		{"approveAdditions asks when additions come with removals", approveAdditions, mixed, true},
		{"approveAdditions ignores skipped removals", approveAdditions, skippedOnly, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.appr.needsPrompt(tt.plan); got != tt.want {
				t.Errorf("needsPrompt = %v, want %v", got, tt.want)
			}
		})
	}
}
