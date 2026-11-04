// Package audit records every tool call and admin change, and sends the records to sinks.
package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time       time.Time      `json:"time"`
	Kind       string         `json:"kind"`
	RequestID  string         `json:"request_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	Instance   string         `json:"instance,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	Groups     []string       `json:"groups,omitempty"`
	Auth       string         `json:"auth,omitempty"`
	Project    string         `json:"project,omitempty"`
	Server     string         `json:"server,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Decision   string         `json:"decision,omitempty"`
	Rule       string         `json:"rule,omitempty"`
	Outcome    string         `json:"outcome,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	Args       map[string]any `json:"args,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// Kinds of audit record.
const (
	KindTool  = "tool"
	KindAdmin = "admin"
)

// Outcomes of a tool call.
const (
	OutcomeOK                 = "ok"
	OutcomeToolError          = "tool_error"
	OutcomeDenied             = "denied"
	OutcomeRateLimited        = "rate_limited"
	OutcomeBackendUnavailable = "backend_unavailable"
	OutcomeTimeout            = "timeout"
	OutcomeCanceled           = "canceled"
)

// Sink stores audit records.
type Sink interface {
	Write(ctx context.Context, events []Event) error
	Close() error
}

// SinkFactory builds a sink from its JSON config.
type SinkFactory func(cfg json.RawMessage) (Sink, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]SinkFactory{}
)

// RegisterSink makes a sink kind available. It panics if kind is already registered.
func RegisterSink(kind string, f SinkFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[kind]; dup {
		panic("audit: sink registered twice: " + kind)
	}
	registry[kind] = f
}

// LookupSink returns the factory registered for kind.
func LookupSink(kind string) (SinkFactory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[kind]
	return f, ok
}
