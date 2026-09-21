// Package reconcile applies a desired network allowlist and port mapping set
// to a sandbox in sbx. It knows nothing about .sbx/policy.yaml or the
// remembered state: callers hand it plain data (Desired) and get back a Plan
// they can show, then Apply. Reading and writing the policy file stays in
// the config package.
package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/daliendev/sbx-policy/internal/sbx"
)

// Backend is the part of sbx the Service drives. *sbx.Client implements it.
type Backend interface {
	ListScopedNetworkRules(sandbox string) ([]sbx.NetworkRule, error)
	AddNetworkRules(hosts []string, sandbox string) error
	RemoveNetworkRuleByID(ruleID string, sandbox string) error
	ListPorts(sandbox string) ([]string, error)
	PublishPort(mapping string, sandbox string) error
	UnpublishPort(mapping string, sandbox string) error
}

// Desired is the state a project wants a sandbox to be in.
type Desired struct {
	Allowlist []string
	Ports     []string
}

// Plan lists what it takes to move a sandbox from its current state to a
// Desired one. The zero value is an empty plan.
type Plan struct {
	// AddHosts are allowlist entries missing from sbx.
	AddHosts []string
	// RemoveRules are sandbox-scoped rules sbx has but Desired does not.
	RemoveRules []sbx.NetworkRule
	// SkippedRemovals are hosts that should be removed but belong to a rule
	// bundling several resources under one ID; removing it would take its
	// siblings with it, so they are left alone (and reported).
	SkippedRemovals []string
	// Unpublish are current port mappings Desired does not ask for.
	Unpublish []string
	// Publish are desired port mappings with no match among the current ones.
	Publish []string
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool {
	return len(p.AddHosts) == 0 && len(p.RemoveRules) == 0 &&
		len(p.Unpublish) == 0 && len(p.Publish) == 0
}

// RemovedHosts returns the hosts RemoveRules would revoke.
func (p Plan) RemovedHosts() []string {
	hosts := make([]string, 0, len(p.RemoveRules))
	for _, r := range p.RemoveRules {
		hosts = append(hosts, r.Host)
	}
	return hosts
}

// PublishError reports that sbx refused to publish one port mapping (e.g.
// the host port is already in use), as opposed to a failure elsewhere in
// Apply. Callers can errors.As it to tell which entry is at fault.
type PublishError struct {
	Mapping string
	Err     error
}

func (e *PublishError) Error() string { return e.Err.Error() }
func (e *PublishError) Unwrap() error { return e.Err }

// Current is a sandbox's state as sbx reports it.
type Current struct {
	Rules []sbx.NetworkRule
	Ports []string
}

// Adopt returns local with sbx's current state folded in, for pulling sbx
// changes into the policy file without rewriting what already matches:
//   - an entry of local that sbx still satisfies is kept as written, in its
//     original position (a bare "3000" stays "3000" while sbx has some
//     "49152:3000", instead of being pinned to the host port sbx chose);
//   - an entry of local that sbx no longer satisfies is dropped;
//   - what sbx has that no entry of local covers is appended, sorted.
//
// It is pure and idempotent: Adopt(Adopt(l, c), c) equals Adopt(l, c).
func Adopt(local Desired, cur Current) Desired {
	hosts := make([]string, 0, len(cur.Rules))
	for _, r := range cur.Rules {
		hosts = append(hosts, r.Host)
	}

	var out Desired
	inSbx := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		inSbx[h] = struct{}{}
	}
	tracked := make(map[string]struct{}, len(local.Allowlist))
	for _, h := range local.Allowlist {
		tracked[h] = struct{}{}
		if _, ok := inSbx[h]; ok {
			out.Allowlist = append(out.Allowlist, h)
		}
	}
	var untracked []string
	for _, h := range hosts {
		if _, ok := tracked[h]; !ok {
			untracked = append(untracked, h)
		}
	}
	out.Allowlist = append(out.Allowlist, sortedUnique(untracked)...)

	var untrackedPorts []string
	for _, d := range local.Ports {
		for _, c := range cur.Ports {
			if portMatchesDesired(c, d) {
				out.Ports = append(out.Ports, d)
				break
			}
		}
	}
	for _, c := range cur.Ports {
		if !matchesAny(c, local.Ports) {
			untrackedPorts = append(untrackedPorts, c)
		}
	}
	out.Ports = append(out.Ports, sortedUnique(untrackedPorts)...)
	return out
}

func sortedUnique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, e := range in {
		if _, ok := seen[e]; !ok {
			seen[e] = struct{}{}
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// Diff computes the plan that turns the current state (network rules scoped
// to the sandbox, and its port mappings) into desired. It is pure.
//
// Bare desired ports like "3000" are satisfied by any current mapping whose
// sandbox port is 3000 (e.g. "49152:3000"), reflecting Docker-style behaviour.
func Diff(desired Desired, currentRules []sbx.NetworkRule, currentPorts []string) Plan {
	var plan Plan

	// Network allowlist.
	currentByHost := make(map[string]string, len(currentRules)) // host -> rule ID ("" if not individually removable)
	for _, r := range currentRules {
		currentByHost[r.Host] = r.ID
	}
	desiredHosts := make(map[string]struct{}, len(desired.Allowlist))
	for _, h := range desired.Allowlist {
		desiredHosts[h] = struct{}{}
		if _, ok := currentByHost[h]; !ok {
			plan.AddHosts = append(plan.AddHosts, h)
		}
	}
	extra := make([]string, 0, len(currentByHost))
	for host := range currentByHost {
		if _, ok := desiredHosts[host]; !ok {
			extra = append(extra, host)
		}
	}
	sort.Strings(extra)
	for _, host := range extra {
		if id := currentByHost[host]; id != "" {
			plan.RemoveRules = append(plan.RemoveRules, sbx.NetworkRule{ID: id, Host: host})
		} else {
			plan.SkippedRemovals = append(plan.SkippedRemovals, host)
		}
	}

	// Ports.
	for _, cur := range currentPorts {
		if !matchesAny(cur, desired.Ports) {
			plan.Unpublish = append(plan.Unpublish, cur)
		}
	}
	for _, d := range desired.Ports {
		satisfied := false
		for _, cur := range currentPorts {
			if portMatchesDesired(cur, d) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			plan.Publish = append(plan.Publish, d)
		}
	}

	return plan
}

func matchesAny(current string, desired []string) bool {
	for _, d := range desired {
		if portMatchesDesired(current, d) {
			return true
		}
	}
	return false
}

// portMatchesDesired reports whether a current port mapping satisfies a
// desired entry. An exact match always satisfies. Additionally, a bare
// desired port like "3000" matches any current mapping whose sandbox
// port is 3000 (e.g. "49152:3000").
func portMatchesDesired(current, desired string) bool {
	if current == desired {
		return true
	}
	if !strings.Contains(desired, ":") {
		return strings.HasSuffix(current, ":"+desired)
	}
	return false
}

// Service reads a sandbox's current state from sbx and applies plans to it.
type Service struct {
	backend Backend
}

// New returns a Service driving backend.
func New(backend Backend) *Service {
	return &Service{backend: backend}
}

// Current reads the sandbox's current state from sbx.
func (s *Service) Current(sandbox string) (Current, error) {
	rules, err := s.backend.ListScopedNetworkRules(sandbox)
	if err != nil {
		return Current{}, fmt.Errorf("unable to read current sbx network rules: %w", err)
	}
	ports, err := s.backend.ListPorts(sandbox)
	if err != nil {
		return Current{}, fmt.Errorf("unable to read current sbx ports: %w", err)
	}
	return Current{Rules: rules, Ports: ports}, nil
}

// Plan reads the sandbox's current state and returns what it takes to reach
// desired. It changes nothing; if the current state can't be read it fails
// rather than guessing.
func (s *Service) Plan(sandbox string, desired Desired) (Plan, error) {
	cur, err := s.Current(sandbox)
	if err != nil {
		return Plan{}, err
	}
	return Diff(desired, cur.Rules, cur.Ports), nil
}

// Apply executes plan against sandbox: network rules first (adds, then
// removals), then ports (unpublish, then publish). It stops at the first
// error. A publish failure is returned as a *PublishError.
func (s *Service) Apply(sandbox string, plan Plan) error {
	if err := s.backend.AddNetworkRules(plan.AddHosts, sandbox); err != nil {
		return err
	}
	for _, r := range plan.RemoveRules {
		if err := s.backend.RemoveNetworkRuleByID(r.ID, sandbox); err != nil {
			return err
		}
	}
	for _, m := range plan.Unpublish {
		if err := s.backend.UnpublishPort(m, sandbox); err != nil {
			return err
		}
	}
	for _, m := range plan.Publish {
		if err := s.backend.PublishPort(m, sandbox); err != nil {
			return &PublishError{Mapping: m, Err: err}
		}
	}
	return nil
}
