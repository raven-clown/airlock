// Package rules is the built-in policy: allow and deny tool patterns per subject, where deny wins.
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/raven-clown/airlock/policy"
	"github.com/raven-clown/airlock/policy/glob"
)

// DefaultDeny names the decision when no rule allows a tool.
const DefaultDeny = "default-deny"

// Rule grants or denies tool patterns to subjects.
type Rule struct {
	Name     string   `json:"name" yaml:"name"`
	Subjects []string `json:"subjects" yaml:"subjects"`
	Allow    []string `json:"allow,omitempty" yaml:"allow"`
	Deny     []string `json:"deny,omitempty" yaml:"deny"`
}

// Policy evaluates rules. Every rule matching the caller counts, any deny wins, and the default is deny.
type Policy struct {
	rules []Rule
}

// New validates rs and returns a policy over them.
func New(rs []Rule) (*Policy, error) {
	seen := map[string]bool{}
	for i, r := range rs {
		if r.Name == "" {
			return nil, fmt.Errorf("rules[%d]: name is empty", i)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("rules[%d]: duplicate name %q", i, r.Name)
		}
		seen[r.Name] = true
		if len(r.Subjects) == 0 {
			return nil, fmt.Errorf("rule %q: no subjects", r.Name)
		}
		for _, s := range r.Subjects {
			if !validSubject(s) {
				return nil, fmt.Errorf("rule %q: unknown subject %q, want user:, group:, key: or *", r.Name, s)
			}
		}
	}
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(a, b Rule) int { return strings.Compare(a.Name, b.Name) })
	return &Policy{rules: sorted}, nil
}

func validSubject(s string) bool {
	if s == "*" {
		return true
	}
	kind, value, ok := strings.Cut(s, ":")
	return ok && value != "" && (kind == "user" || kind == "group" || kind == "key")
}

// Decide implements policy.Policy.
func (p *Policy) Decide(_ context.Context, req policy.Request) policy.Decision {
	subjects := policy.Subjects(req.Identity)
	var allow *policy.Decision
	for _, r := range p.rules {
		if !matchesSubject(r.Subjects, subjects) {
			continue
		}
		if pat, ok := firstMatch(r.Deny, req.Tool); ok {
			return policy.Decision{Rule: r.Name, Reason: "denied by pattern " + pat}
		}
		if allow == nil {
			if pat, ok := firstMatch(r.Allow, req.Tool); ok {
				allow = &policy.Decision{Allow: true, Rule: r.Name, Reason: "allowed by pattern " + pat}
			}
		}
	}
	if allow != nil {
		return *allow
	}
	return policy.Decision{Rule: DefaultDeny, Reason: "no rule allows " + req.Tool}
}

func matchesSubject(ruleSubjects, callerSubjects []string) bool {
	for _, s := range ruleSubjects {
		if slices.Contains(callerSubjects, s) {
			return true
		}
	}
	return false
}

func firstMatch(patterns []string, tool string) (string, bool) {
	for _, pat := range patterns {
		if glob.Match(pat, tool) {
			return pat, true
		}
	}
	return "", false
}

type config struct {
	Rules []Rule `json:"rules"`
}

func init() {
	policy.Register("rules", func(raw json.RawMessage) (policy.Policy, error) {
		var c config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("rules config: %w", err)
		}
		return New(c.Rules)
	})
}
