// Package policy decides whether a caller may see or call a tool.
package policy

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/raven-clown/airlock/auth"
)

// Request is one question to a policy. Tool is the prefixed name.
// Args is nil when filtering tools/list and set on tools/call.
type Request struct {
	Identity *auth.Identity
	Server   string
	Tool     string
	Args     map[string]any
}

// Decision is a policy's answer, with the rule that decided it.
type Decision struct {
	Allow  bool
	Rule   string
	Reason string
}

// Policy decides tool access.
type Policy interface {
	Decide(ctx context.Context, req Request) Decision
}

// Subjects lists the subject strings an identity matches in rules:
// user:<subject> or key:<name>, then group:<name> for each group, then *.
func Subjects(id *auth.Identity) []string {
	if id == nil {
		return nil
	}
	var out []string
	if id.KeyName != "" {
		out = append(out, "key:"+id.KeyName)
	} else {
		out = append(out, "user:"+id.Subject)
	}
	for _, g := range id.Groups {
		out = append(out, "group:"+g)
	}
	return append(out, "*")
}

// Factory builds a policy from its JSON config.
type Factory func(cfg json.RawMessage) (Policy, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register makes a policy kind available. It panics if kind is already registered.
func Register(kind string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[kind]; dup {
		panic("policy: kind registered twice: " + kind)
	}
	registry[kind] = f
}

// Lookup returns the factory registered for kind.
func Lookup(kind string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[kind]
	return f, ok
}
