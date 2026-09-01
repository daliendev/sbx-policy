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
