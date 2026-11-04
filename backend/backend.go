package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth"
)

// Backend is one MCP server behind airlock.
type Backend interface {
	Name() string
	// Start begins connecting in the background. A server that cannot be reached
	// shows up in Status, not as an error here.
	Start(ctx context.Context) error
	// Tools returns the last known tools, with their original names.
	Tools() []mcp.Tool
	// Call runs a tool by its original name.
	Call(ctx context.Context, id *auth.Identity, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
	Status() Status
	Close() error
	// OnToolsChanged registers fn to run whenever Tools changes.
	OnToolsChanged(fn func())
}

// Backend states.
const (
	StateStarting = "starting"
	StateUp       = "up"
	StateDown     = "down"
)

// Status is a backend's current state.
type Status struct {
	State  string    `json:"state"`
	Err    string    `json:"error,omitempty"`
	Tools  int       `json:"tools"`
	Since  time.Time `json:"since"`
	Stderr []string  `json:"stderr,omitempty"`
}

// Up reports whether the backend is connected.
func (s Status) Up() bool { return s.State == StateUp }

// ErrUnavailable is returned by Call when the backend is not connected.
var ErrUnavailable = errors.New("backend unavailable")

// Deps are what a backend may use from airlock.
type Deps struct {
	Logger *slog.Logger
	// Env resolves ${VAR} references in server definitions.
	Env func(string) (string, bool)
}

// Factory builds a backend for one transport.
type Factory func(cfg Config, deps Deps) (Backend, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register makes a transport available. It panics if transport is already registered.
func Register(transport string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[transport]; dup {
		panic("backend: transport registered twice: " + transport)
	}
	registry[transport] = f
}

func lookup(transport string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[transport]
	return f, ok
}

// ToolLister is the part of an MCP client ListAllTools needs.
type ToolLister interface {
	ListTools(ctx context.Context, req mcp.ListToolsRequest) (*mcp.ListToolsResult, error)
}

// ListAllTools follows pagination until every tool is listed.
func ListAllTools(ctx context.Context, c ToolLister) ([]mcp.Tool, error) {
	var tools []mcp.Tool
	var req mcp.ListToolsRequest
	for {
		res, err := c.ListTools(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("listing tools: %w", err)
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" {
			return tools, nil
		}
		req.Params.Cursor = res.NextCursor
	}
}
