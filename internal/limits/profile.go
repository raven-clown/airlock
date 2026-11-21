// Package limits applies the shared mothership profiles to airlock's requests and tool calls.
package limits

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/raven-clown/airlock/ratelimit"
)

// The limit keys airlock owns. Keys under the other projects' prefixes are ignored.
const (
	KeyRequests  = "requests"
	KeyToolCalls = "tools.calls"
)

var otherProjects = []string{"llm.", "agent.", "memory."}

// Spec is a profile as the config file and the admin API write it.
type Spec struct {
	Name     string         `json:"name" yaml:"name"`
	Priority int            `json:"priority,omitempty" yaml:"priority"`
	Limits   map[string]any `json:"limits,omitempty" yaml:"limits"`
}

// Limit is a rate and a cap on calls running at once. Zero values mean no limit.
type Limit struct {
	Rate        *ratelimit.Rate
	Concurrency int64
}

func (l Limit) empty() bool { return l.Rate == nil && l.Concurrency == 0 }

// Profile is a named set of limits.
type Profile struct {
	Name      string
	Priority  int
	Requests  Limit
	ToolCalls Limit
}

// ParseProfile reads a profile's limits.
func ParseProfile(s Spec) (Profile, error) {
	p := Profile{Name: s.Name, Priority: s.Priority}
	keys := make([]string, 0, len(s.Limits))
	for k := range s.Limits {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		var err error
		switch key {
		case KeyRequests:
			p.Requests, err = parseLimit(s.Limits[key])
		case KeyToolCalls:
			p.ToolCalls, err = parseLimit(s.Limits[key])
		default:
			if ownedElsewhere(key) {
				continue
			}
			return Profile{}, fmt.Errorf("profile %q: unknown limit %q", s.Name, key)
		}
		if err != nil {
			return Profile{}, fmt.Errorf("profile %q: %s: %w", s.Name, key, err)
		}
	}
	return p, nil
}

func ownedElsewhere(key string) bool {
	for _, prefix := range otherProjects {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func parseLimit(v any) (Limit, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Limit{}, fmt.Errorf("must be a map of rate and concurrency")
	}
	var l Limit
	for _, field := range slices.Sorted(mapKeys(m)) {
		switch field {
		case "rate":
			s, _ := m[field].(string)
			r, err := ratelimit.ParseRate(s)
			if err != nil {
				return Limit{}, fmt.Errorf("rate: %w", err)
			}
			l.Rate = &r
		case "concurrency":
			n, ok := wholeNumber(m[field])
			if !ok {
				return Limit{}, fmt.Errorf("concurrency: %v must be a whole number of zero or more", m[field])
			}
			l.Concurrency = n
		default:
			return Limit{}, fmt.Errorf("unknown field %q", field)
		}
	}
	return l, nil
}

func mapKeys(m map[string]any) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// wholeNumber reads an int from YAML or a float64 from JSON.
func wholeNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), n >= 0
	case int64:
		return n, n >= 0
	case float64:
		if n < 0 || n != math.Trunc(n) || n > 1<<53 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

// Binding gives the subject a profile. Subjects are key:<name>, user:<subject> or group:<name>.
type Binding struct {
	Name    string `json:"name" yaml:"name"`
	Subject string `json:"subject" yaml:"subject"`
	Profile string `json:"profile" yaml:"profile"`
}

// Config is everything the limiter enforces.
type Config struct {
	Profiles []Profile
	Bindings []Binding
	// Default applies to a caller nothing else gives a profile. Org applies to every call
	// on top of the caller's profile.
	Default, Org string
}

// Validate checks names and references.
func (c Config) Validate() error {
	known := map[string]bool{}
	for i, p := range c.Profiles {
		switch {
		case p.Name == "":
			return fmt.Errorf("profiles[%d].name: required", i)
		case known[p.Name]:
			return fmt.Errorf("profiles[%d].name: duplicate %q", i, p.Name)
		}
		known[p.Name] = true
	}
	seen := map[string]bool{}
	for i, b := range c.Bindings {
		at := fmt.Sprintf("profile_bindings[%d]", i)
		kind, value, _ := strings.Cut(b.Subject, ":")
		switch {
		case b.Name == "":
			return fmt.Errorf("%s.name: required", at)
		case seen[b.Name]:
			return fmt.Errorf("%s.name: duplicate %q", at, b.Name)
		case value == "" || (kind != "key" && kind != "user" && kind != "group"):
			return fmt.Errorf("%s.subject: %q must be key:<name>, user:<subject> or group:<name>", at, b.Subject)
		case !known[b.Profile]:
			return fmt.Errorf("%s.profile: unknown profile %q", at, b.Profile)
		}
		seen[b.Name] = true
	}
	if c.Default != "" && !known[c.Default] {
		return fmt.Errorf("default_profile: unknown profile %q", c.Default)
	}
	if c.Org != "" && !known[c.Org] {
		return fmt.Errorf("org_profile: unknown profile %q", c.Org)
	}
	return nil
}
