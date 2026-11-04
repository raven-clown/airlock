package streamable

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/httpx"
	"github.com/raven-clown/airlock/internal/testutil/mcpserver"
)

type seen struct {
	Method  string
	RPC     string
	Header  http.Header
	Session string
}

type recorder struct {
	mu   sync.Mutex
	reqs []seen
	next http.Handler
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Method string `json:"method"`
	}
	if req.Body != nil {
		data, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(data, &body)
		req.Body = io.NopCloser(bytes.NewReader(data))
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, seen{Method: req.Method, RPC: body.Method, Header: req.Header.Clone(), Session: req.Header.Get("Mcp-Session-Id")})
	r.mu.Unlock()
	r.next.ServeHTTP(w, req)
}

func (r *recorder) all() []seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]seen(nil), r.reqs...)
}

func newServer(t *testing.T) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{next: server.NewStreamableHTTPServer(mcpserver.New("remote"))}
	ts := httptest.NewServer(rec)
	t.Cleanup(ts.Close)
	return ts, rec
}

var testOpts = Options{BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond, CheckEvery: 20 * time.Millisecond}

func start(t *testing.T, cfg backend.Config, opts Options) *Backend {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "remote"
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 5 * time.Second
	}
	if cfg.Auth.Mode == "" {
		cfg.Auth.Mode = backend.AuthNone
	}
	b := New(cfg, backend.Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, opts)
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	waitFor(t, "backend up", func() bool { return b.Status().Up() })
	return b
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func echo(ctx context.Context, b *Backend, id *auth.Identity, s string) (string, error) {
	req := mcp.CallToolRequest{}
	req.Params.Name = "echo"
	req.Params.Arguments = map[string]any{"text": s}
	res, err := b.Call(ctx, id, req)
	if err != nil {
		return "", err
	}
	tc, _ := res.Content[0].(mcp.TextContent)
	return tc.Text, nil
}

func callsWith(rec *recorder, header, value string) []seen {
	var out []seen
	for _, r := range rec.all() {
		if r.Method == http.MethodPost && r.Header.Get(header) == value {
			out = append(out, r)
		}
	}
	return out
}

func TestHTTPNone(t *testing.T) {
	ts, rec := newServer(t)
	b := start(t, backend.Config{URL: ts.URL}, testOpts)
	if len(b.Tools()) == 0 {
		t.Fatal("no tools listed")
	}
	got, err := echo(context.Background(), b, nil, "hi")
	if err != nil || got != "hi" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	for _, r := range rec.all() {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("Authorization sent in none mode")
		}
	}
}

func TestHTTPStatic(t *testing.T) {
	ts, rec := newServer(t)
	b := start(t, backend.Config{URL: ts.URL, Auth: backend.HTTPAuth{Mode: backend.AuthStatic, Headers: map[string]string{"X-Key": "abc"}}}, testOpts)
	if _, err := echo(context.Background(), b, nil, "hi"); err != nil {
		t.Fatal(err)
	}
	for _, r := range rec.all() {
		if r.Header.Get("X-Key") != "abc" {
			t.Fatalf("%s request without X-Key", r.Method)
		}
	}
}

func TestHTTPForward(t *testing.T) {
	ts, rec := newServer(t)
	b := start(t, backend.Config{URL: ts.URL, Auth: backend.HTTPAuth{Mode: backend.AuthForward, DiscoveryHeaders: map[string]string{"Authorization": "Bearer discovery"}}}, testOpts)
	alice := &auth.Identity{Subject: "alice", Token: "ta"}
	bob := &auth.Identity{Subject: "bob", Token: "tb"}
	ctx := context.Background()
	for _, id := range []*auth.Identity{alice, bob, alice} {
		if _, err := echo(ctx, b, id, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if got := rpcCount(rec, "Bearer ta", "tools/call"); got != 2 {
		t.Errorf("alice made %d calls with her token, want 2", got)
	}
	if got := rpcCount(rec, "Bearer tb", "tools/call"); got != 1 {
		t.Errorf("bob made %d calls with his token, want 1", got)
	}
	if got := handshakes(rec, "Bearer ta"); got != 1 {
		t.Errorf("alice's upstream client was initialized %d times, want 1", got)
	}
	for _, r := range rec.all() {
		if r.RPC == "tools/call" && r.Header.Get("Authorization") == "Bearer discovery" {
			t.Fatal("a caller's tool call used the discovery headers")
		}
	}
	if len(callsWith(rec, "Authorization", "Bearer discovery")) == 0 {
		t.Error("discovery headers not used for listing")
	}
}

func TestHTTPForwardNeedsIdentity(t *testing.T) {
	ts, _ := newServer(t)
	b := start(t, backend.Config{URL: ts.URL, Auth: backend.HTTPAuth{Mode: backend.AuthForward}}, testOpts)
	if _, err := echo(context.Background(), b, nil, "x"); err == nil {
		t.Fatal("forward call without identity succeeded")
	}
}

func TestHTTPPoolEviction(t *testing.T) {
	ts, rec := newServer(t)
	now := time.Now()
	var clockMu sync.Mutex
	opts := testOpts
	opts.Now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	b := start(t, backend.Config{URL: ts.URL, Auth: backend.HTTPAuth{Mode: backend.AuthForward, MaxSessions: 1, SessionIdleTimeout: 50 * time.Millisecond}}, opts)
	ctx := context.Background()
	if _, err := echo(ctx, b, &auth.Identity{Subject: "alice", Token: "ta"}, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := echo(ctx, b, &auth.Identity{Subject: "bob", Token: "tb"}, "x"); err != nil {
		t.Fatal(err)
	}
	if b.pool.len() != 1 {
		t.Fatalf("pool has %d sessions", b.pool.len())
	}
	clockMu.Lock()
	now = now.Add(time.Minute)
	clockMu.Unlock()
	b.pool.sweep()
	if b.pool.len() != 0 {
		t.Fatal("idle session not swept")
	}
	if _, err := echo(ctx, b, &auth.Identity{Subject: "alice", Token: "ta"}, "x"); err != nil {
		t.Fatal(err)
	}
	if got := handshakes(rec, "Bearer ta"); got != 2 {
		t.Errorf("alice's evicted client was not replaced: %d initializes", got)
	}
}

// handshakes counts initialize (2025 protocol) and server/discover (2026 protocol) requests.
func handshakes(rec *recorder, auth string) int {
	return rpcCount(rec, auth, "initialize") + rpcCount(rec, auth, "server/discover")
}

func rpcCount(rec *recorder, auth, method string) int {
	n := 0
	for _, r := range rec.all() {
		if r.RPC == method && r.Header.Get("Authorization") == auth {
			n++
		}
	}
	return n
}

func TestHTTPTraceHeaders(t *testing.T) {
	ts, rec := newServer(t)
	b := start(t, backend.Config{URL: ts.URL}, testOpts)
	h := http.Header{}
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("X-Request-ID", "req-1")
	ctx := httpx.WithForwardHeaders(context.Background(), h)
	if _, err := echo(ctx, b, nil, "x"); err != nil {
		t.Fatal(err)
	}
	if len(callsWith(rec, "X-Request-Id", "req-1")) != 1 || len(callsWith(rec, "Traceparent", h.Get("Traceparent"))) != 1 {
		t.Error("trace headers not forwarded on the call")
	}
}

func TestHTTPServerDown(t *testing.T) {
	ts, _ := newServer(t)
	b := start(t, backend.Config{URL: ts.URL, CallTimeout: time.Second}, testOpts)
	ts.Close()
	waitFor(t, "backend down", func() bool { return b.Status().State == backend.StateDown })
	if _, err := echo(context.Background(), b, nil, "x"); !errors.Is(err, backend.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestHTTPListChanged(t *testing.T) {
	ts, _ := newServer(t)
	b := start(t, backend.Config{URL: ts.URL}, testOpts)
	changed := make(chan struct{}, 10)
	b.OnToolsChanged(func() { changed <- struct{}{} })
	req := mcp.CallToolRequest{}
	req.Params.Name = "add_tool"
	req.Params.Arguments = map[string]any{"name": "new"}
	if _, err := b.Call(context.Background(), nil, req); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new tool listed", func() bool {
		for _, tool := range b.Tools() {
			if tool.Name == "new" {
				return true
			}
		}
		return false
	})
	select {
	case <-changed:
	default:
		t.Fatal("OnToolsChanged did not fire")
	}
}

func TestHTTPNoChangeNoCallback(t *testing.T) {
	ts, _ := newServer(t)
	b := start(t, backend.Config{URL: ts.URL}, testOpts)
	calls := 0
	var mu sync.Mutex
	b.OnToolsChanged(func() { mu.Lock(); calls++; mu.Unlock() })
	b.mu.Lock()
	control := b.control
	b.mu.Unlock()
	if err := b.refresh(control); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("callback fired %d times for an unchanged list", calls)
	}
}

func TestRegistered(t *testing.T) {
	ts, _ := newServer(t)
	s := backend.NewSet(backend.Deps{})
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Apply(context.Background(), []backend.Config{{Name: "r", Transport: backend.TransportStreamable, URL: ts.URL, CallTimeout: time.Second, Auth: backend.HTTPAuth{Mode: backend.AuthNone}}}); err != nil {
		t.Fatal(err)
	}
	b, _ := s.Get("r")
	waitFor(t, "registered backend up", func() bool { return b.Status().Up() })
}
