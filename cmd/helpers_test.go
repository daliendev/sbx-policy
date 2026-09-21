package cmd

import (
	"reflect"
	"testing"
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

func TestResolveSandbox(t *testing.T) {
	tests := []struct {
		name         string
		flag, policy string
		want         string
	}{
		{"flag wins over policy", "from-flag", "from-policy", "from-flag"},
		{"policy when no flag", "", "from-policy", "from-policy"},
		{"nothing set", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveSandbox(tt.flag, tt.policy); got != tt.want {
				t.Errorf("resolveSandbox(%q, %q) = %q, want %q", tt.flag, tt.policy, got, tt.want)
			}
		})
	}
}
