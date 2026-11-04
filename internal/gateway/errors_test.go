package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/policy/rules"
)

type erroringBackend struct{ err error }

func (e erroringBackend) Name() string                { return "broken" }
func (e erroringBackend) Start(context.Context) error { return nil }
func (e erroringBackend) Tools() []mcp.Tool           { return []mcp.Tool{mcp.NewTool("echo")} }
func (e erroringBackend) Call(context.Context, *auth.Identity, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return nil, e.err
}
func (e erroringBackend) Status() backend.Status { return backend.Status{State: backend.StateUp} }
func (e erroringBackend) Close() error           { return nil }
func (e erroringBackend) OnToolsChanged(func())  {}

var backendErr error

func init() {
	backend.Register("erroring", func(backend.Config, backend.Deps) (backend.Backend, error) {
		return erroringBackend{err: backendErr}, nil
	})
}

func TestUpstreamCancelIsUnavailable(t *testing.T) {
	backendErr = fmt.Errorf("transport error: %w", context.Canceled)
	set := backend.NewSet(backend.Deps{})
	if err := set.Apply(context.Background(), []backend.Config{{Name: "broken", Transport: "erroring"}}); err != nil {
		t.Fatal(err)
	}
	snap, err := runtime.Build(&config.Config{
		APIKeys: []apikey.Key{{Name: "eng", SHA256: apikey.Hash(engKey), Groups: []string{"eng"}}},
		Rules:   []rules.Rule{{Name: "eng", Subjects: []string{"group:eng"}, Allow: []string{"*"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	pipe := audit.NewPipeline([]audit.Sink{sink}, audit.PipelineOptions{BatchSize: 1})
	defer func() { _ = pipe.Close(context.Background()) }()
	gw := New(Options{Backends: set, Runtime: runtime.NewHolder(snap), Audit: pipe, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "key:eng", KeyName: "eng", Groups: []string{"eng"}})
	req := mcp.CallToolRequest{}
	req.Params.Name = "broken__echo"
	res, err := gw.handler("broken", "echo")(ctx, req)
	if err != nil || !res.IsError || text(res) != "server broken is unavailable" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	sink.find(t, func(e audit.Event) bool { return e.Outcome == audit.OutcomeBackendUnavailable })

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := gw.handler("broken", "echo")(canceled, req); err == nil {
		t.Fatal("a call the caller canceled returned no error")
	}
	sink.find(t, func(e audit.Event) bool { return e.Outcome == audit.OutcomeCanceled })
}
