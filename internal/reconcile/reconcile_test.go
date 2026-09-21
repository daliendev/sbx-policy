package reconcile

import (
	"errors"
	"reflect"
	"testing"

	"github.com/daliendev/sbx-policy/internal/sbx"
)

func TestDiffIdempotent(t *testing.T) {
	plan := Diff(
		Desired{Allowlist: []string{"github.com", "example.com"}, Ports: []string{"8080:3000"}},
		[]sbx.NetworkRule{{ID: "r1", Host: "github.com"}, {ID: "r2", Host: "example.com"}},
		[]string{"8080:3000"},
	)
	if !plan.Empty() || len(plan.SkippedRemovals) != 0 {
		t.Fatalf("expected empty plan, got %+v", plan)
	}
}

func TestDiffNetwork(t *testing.T) {
	tests := []struct {
		name    string
		desired []string
		current []sbx.NetworkRule
		want    Plan
	}{
		{
			name:    "adds missing hosts",
			desired: []string{"new.com", "other.com"},
			want:    Plan{AddHosts: []string{"new.com", "other.com"}},
		},
		{
			name:    "removes extra rules by ID, sorted by host",
			desired: []string{"github.com"},
			current: []sbx.NetworkRule{{ID: "r-z", Host: "z.com"}, {ID: "r-gh", Host: "github.com"}, {ID: "r-a", Host: "a.com"}},
			want:    Plan{RemoveRules: []sbx.NetworkRule{{ID: "r-a", Host: "a.com"}, {ID: "r-z", Host: "z.com"}}},
		},
		{
			// A bundled rule has no ID: removing it would take its siblings
			// with it, so it is reported instead of removed.
			name:    "bundled rules are skipped, not removed",
			current: []sbx.NetworkRule{{Host: "b.com"}, {Host: "a.com"}},
			want:    Plan{SkippedRemovals: []string{"a.com", "b.com"}},
		},
		{
			name:    "add and remove together",
			desired: []string{"new.com"},
			current: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}},
			want:    Plan{AddHosts: []string{"new.com"}, RemoveRules: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Diff(Desired{Allowlist: tt.desired}, tt.current, nil)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDiffPorts(t *testing.T) {
	tests := []struct {
		name    string
		desired []string
		current []string
		want    Plan
	}{
		{"publishes missing", []string{"8080:3000"}, nil, Plan{Publish: []string{"8080:3000"}}},
		{"unpublishes extra", nil, []string{"9090:9000"}, Plan{Unpublish: []string{"9090:9000"}}},
		{"exact match is left alone", []string{"8080:3000"}, []string{"8080:3000"}, Plan{}},
		{
			// "3000" lets the OS pick the host port; once sbx has chosen 49152
			// the bare entry must not be re-published or the mapping removed.
			name:    "bare port matches any host port",
			desired: []string{"3000"},
			current: []string{"49152:3000"},
			want:    Plan{},
		},
		{"bare port does not match another sandbox port", []string{"3000"}, []string{"49152:30001"}, Plan{Publish: []string{"3000"}, Unpublish: []string{"49152:30001"}}},
		{"replaces a mapping", []string{"18080:3000"}, []string{"8080:3000"}, Plan{Publish: []string{"18080:3000"}, Unpublish: []string{"8080:3000"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Diff(Desired{Ports: tt.desired}, nil, tt.current)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// fakeBackend serves a fixed current state and records mutations in order.
type fakeBackend struct {
	rules    []sbx.NetworkRule
	ports    []string
	listErr  error
	failOn   string // operation string that fails, e.g. "publish 8080:3000"
	failWith error
	ops      []string
}

func (f *fakeBackend) do(op string) error {
	f.ops = append(f.ops, op)
	if op == f.failOn {
		return f.failWith
	}
	return nil
}

func (f *fakeBackend) ListScopedNetworkRules(string) ([]sbx.NetworkRule, error) {
	return f.rules, f.listErr
}
func (f *fakeBackend) ListPorts(string) ([]string, error) { return f.ports, nil }
func (f *fakeBackend) AddNetworkRules(hosts []string, _ string) error {
	if len(hosts) == 0 {
		return nil
	}
	return f.do("add " + hosts[0])
}
func (f *fakeBackend) RemoveNetworkRuleByID(id, _ string) error { return f.do("rm " + id) }
func (f *fakeBackend) PublishPort(m, _ string) error            { return f.do("publish " + m) }
func (f *fakeBackend) UnpublishPort(m, _ string) error          { return f.do("unpublish " + m) }

func TestServicePlanReadsCurrentState(t *testing.T) {
	b := &fakeBackend{
		rules: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}},
		ports: []string{"8080:3000"},
	}
	plan, err := New(b).Plan("box", Desired{Allowlist: []string{"new.com"}, Ports: []string{"9090:9000"}})
	if err != nil {
		t.Fatal(err)
	}
	want := Plan{
		AddHosts:    []string{"new.com"},
		RemoveRules: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}},
		Publish:     []string{"9090:9000"},
		Unpublish:   []string{"8080:3000"},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("got %+v, want %+v", plan, want)
	}
	if len(b.ops) != 0 {
		t.Fatalf("Plan must not mutate sbx, got %v", b.ops)
	}
}

// When the current state can't be read there is nothing safe to plan
// against: fail without touching sbx.
func TestServicePlanFailsWhenStateUnreadable(t *testing.T) {
	b := &fakeBackend{listErr: errors.New("sbx policy ls failed")}
	if _, err := New(b).Plan("box", Desired{Allowlist: []string{"a.com"}}); err == nil {
		t.Fatal("expected error")
	}
	if len(b.ops) != 0 {
		t.Fatalf("expected no mutation, got %v", b.ops)
	}
}

func TestServiceApplyOrder(t *testing.T) {
	b := &fakeBackend{}
	plan := Plan{
		AddHosts:    []string{"new.com"},
		RemoveRules: []sbx.NetworkRule{{ID: "r1", Host: "old.com"}},
		Unpublish:   []string{"8080:3000"},
		Publish:     []string{"9090:9000"},
	}
	if err := New(b).Apply("box", plan); err != nil {
		t.Fatal(err)
	}
	want := []string{"add new.com", "rm r1", "unpublish 8080:3000", "publish 9090:9000"}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("ops = %v, want %v", b.ops, want)
	}
}

func TestServiceApplyEmptyPlanDoesNothing(t *testing.T) {
	b := &fakeBackend{}
	if err := New(b).Apply("box", Plan{}); err != nil {
		t.Fatal(err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("expected no ops, got %v", b.ops)
	}
}

func TestServiceApplyStopsAtFirstPublishFailure(t *testing.T) {
	cause := errors.New("address already in use")
	b := &fakeBackend{failOn: "publish 49969:49969", failWith: cause}
	plan := Plan{Publish: []string{"18080:3000", "49969:49969", "9090:9000"}}

	err := New(b).Apply("box", plan)

	var pubErr *PublishError
	if !errors.As(err, &pubErr) || pubErr.Mapping != "49969:49969" {
		t.Fatalf("expected *PublishError for 49969:49969, got %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected cause to stay reachable, got %v", err)
	}
	want := []string{"publish 18080:3000", "publish 49969:49969"}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("ops = %v, want %v (must stop at the failure)", b.ops, want)
	}
}

func TestServiceApplyNetworkFailureIsNotAPublishError(t *testing.T) {
	b := &fakeBackend{failOn: "add new.com", failWith: errors.New("boom")}
	err := New(b).Apply("box", Plan{AddHosts: []string{"new.com"}, Publish: []string{"8080:3000"}})

	var pubErr *PublishError
	if err == nil || errors.As(err, &pubErr) {
		t.Fatalf("expected a plain error, got %v", err)
	}
	if !reflect.DeepEqual(b.ops, []string{"add new.com"}) {
		t.Fatalf("ports must not be touched after a network failure, got %v", b.ops)
	}
}

// The service must stay usable with the real client.
var _ Backend = (*sbx.Client)(nil)

func TestAdopt(t *testing.T) {
	rules := func(hosts ...string) []sbx.NetworkRule {
		var r []sbx.NetworkRule
		for _, h := range hosts {
			r = append(r, sbx.NetworkRule{ID: "id-" + h, Host: h})
		}
		return r
	}
	tests := []struct {
		name  string
		local Desired
		cur   Current
		want  Desired
	}{
		{
			// The reported problem: sbx chose host port 49152 for "3000".
			name:  "bare port stays as written while sbx satisfies it",
			local: Desired{Ports: []string{"3000"}},
			cur:   Current{Ports: []string{"49152:3000"}},
			want:  Desired{Ports: []string{"3000"}},
		},
		{
			name:  "adopts what the file doesn't track, sorted, after the file's entries",
			local: Desired{Allowlist: []string{"github.com"}, Ports: []string{"8080:3000"}},
			cur:   Current{Rules: rules("zeta.com", "github.com", "alpha.com"), Ports: []string{"7777:7000", "8080:3000"}},
			want:  Desired{Allowlist: []string{"github.com", "alpha.com", "zeta.com"}, Ports: []string{"8080:3000", "7777:7000"}},
		},
		{
			name:  "drops entries sbx no longer has",
			local: Desired{Allowlist: []string{"a.com", "b.com"}, Ports: []string{"8080:3000", "9090:9000"}},
			cur:   Current{Rules: rules("b.com"), Ports: []string{"9090:9000"}},
			want:  Desired{Allowlist: []string{"b.com"}, Ports: []string{"9090:9000"}},
		},
		{
			name:  "keeps the file's order",
			local: Desired{Allowlist: []string{"z.com", "a.com"}},
			cur:   Current{Rules: rules("a.com", "z.com")},
			want:  Desired{Allowlist: []string{"z.com", "a.com"}},
		},
		{
			name: "adopting into an empty file",
			cur:  Current{Rules: rules("b.com", "a.com"), Ports: []string{"49152:3000"}},
			want: Desired{Allowlist: []string{"a.com", "b.com"}, Ports: []string{"49152:3000"}},
		},
		{
			// A bare port only covers the sandbox port it names.
			name:  "bare port not satisfied is dropped and the real mapping adopted",
			local: Desired{Ports: []string{"3000"}},
			cur:   Current{Ports: []string{"49152:30001"}},
			want:  Desired{Ports: []string{"49152:30001"}},
		},
		{
			// Bundled rules (no ID) are still hosts sbx allows for the sandbox.
			name: "bundled hosts are adopted",
			cur:  Current{Rules: []sbx.NetworkRule{{Host: "a.com"}, {Host: "b.com"}}},
			want: Desired{Allowlist: []string{"a.com", "b.com"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Adopt(tt.local, tt.cur)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			if again := Adopt(got, tt.cur); !reflect.DeepEqual(again, got) {
				t.Errorf("not idempotent: %+v then %+v", got, again)
			}
			// What Adopt returns must leave nothing to sync back up.
			if plan := Diff(got, tt.cur.Rules, tt.cur.Ports); len(plan.AddHosts) != 0 || len(plan.Publish) != 0 {
				t.Errorf("adopted state still needs publishing to sbx: %+v", plan)
			}
		})
	}
}
