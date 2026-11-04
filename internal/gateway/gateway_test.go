package gateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/backend"
	_ "github.com/raven-clown/airlock/backend/streamable"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/testutil/mcpserver"
	"github.com/raven-clown/airlock/policy/rules"
)

const (
	engKey     = apikey.Prefix + "eng"
	internsKey = apikey.Prefix + "interns"
)

type memSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memSink) Write(_ context.Context, es []audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, es...)
	return nil
}

func (m *memSink) Close() error { return nil }

func (m *memSink) find(t *testing.T, match func(audit.Event) bool) audit.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		for _, e := range m.events {
			if match(e) {
				m.mu.Unlock()
				return e
			}
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("audit record not found")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type harness struct {
	gw    *Gateway
	url   string
	sink  *memSink
	logs  *syncBuffer
	alpha *httptest.Server
	set   *backend.Set
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	alpha := httptest.NewServer(server.NewStreamableHTTPServer(mcpserver.New("alpha")))
	beta := httptest.NewServer(server.NewStreamableHTTPServer(mcpserver.New("beta")))
	t.Cleanup(alpha.Close)
	t.Cleanup(beta.Close)

	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	snap, err := runtime.Build(&config.Config{
		APIKeys: []apikey.Key{
			{Name: "eng", SHA256: apikey.Hash(engKey), Groups: []string{"eng"}},
			{Name: "interns", SHA256: apikey.Hash(internsKey), Groups: []string{"interns"}},
		},
		Rules: []rules.Rule{
			{Name: "eng", Subjects: []string{"group:eng"}, Allow: []string{"alpha__*", "beta__*"}},
			{Name: "interns", Subjects: []string{"group:interns"}, Allow: []string{"beta__*"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	set := backend.NewSet(backend.Deps{Logger: log})
	cfgs := []backend.Config{
		{Name: "alpha", Transport: backend.TransportStreamable, URL: alpha.URL, CallTimeout: 2 * time.Second, Auth: backend.HTTPAuth{Mode: backend.AuthNone}},
		{Name: "beta", Transport: backend.TransportStreamable, URL: beta.URL, CallTimeout: 2 * time.Second, Auth: backend.HTTPAuth{Mode: backend.AuthNone}},
	}
	if err := set.Apply(context.Background(), cfgs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	sink := &memSink{}
	pipe := audit.NewPipeline([]audit.Sink{sink}, audit.PipelineOptions{BatchSize: 1, Logger: log})
	t.Cleanup(func() { _ = pipe.Close(context.Background()) })

	gw := New(Options{Backends: set, Runtime: runtime.NewHolder(snap), Audit: pipe, Logger: log, Instance: "test", Version: "test"})
	h := &harness{gw: gw, sink: sink, logs: logs, alpha: alpha, set: set}
	waitFor(t, "backend tools", func() bool {
		names := h.catalogNames()
		return slices.Contains(names, "alpha__echo") && slices.Contains(names, "beta__echo")
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", gw.HTTPHandler())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	h.url = ts.URL + "/mcp"
	return h
}

func (h *harness) catalogNames() []string {
	var names []string
	for _, t := range h.gw.MCPServer().ListTools() {
		names = append(names, t.Tool.Name)
	}
	return names
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

func (h *harness) connect(t *testing.T, key string, opts ...client.ClientOption) *client.Client {
	t.Helper()
	tr, err := transport.NewStreamableHTTP(h.url, transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + key}))
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(tr, opts...)
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	return c
}

func listNames(t *testing.T, c *client.Client) []string {
	t.Helper()
	res, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func callTool(c *client.Client, name string, args map[string]any) (*mcp.CallToolResult, error) {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return c.CallTool(context.Background(), req)
}

func text(r *mcp.CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	tc, _ := r.Content[0].(mcp.TextContent)
	return tc.Text
}

func TestListFiltered(t *testing.T) {
	h := newHarness(t)
	eng := listNames(t, h.connect(t, engKey))
	if !slices.Contains(eng, "alpha__echo") || !slices.Contains(eng, "beta__echo") {
		t.Errorf("eng sees %v", eng)
	}
	interns := listNames(t, h.connect(t, internsKey))
	if slices.Contains(interns, "alpha__echo") || !slices.Contains(interns, "beta__echo") {
		t.Errorf("interns see %v", interns)
	}
}

func TestCallRouted(t *testing.T) {
	h := newHarness(t)
	res, err := callTool(h.connect(t, engKey), "alpha__echo", map[string]any{"text": "hi"})
	if err != nil || text(res) != "hi" {
		t.Fatalf("alpha__echo = %v, %v", res, err)
	}
	e := h.sink.find(t, func(e audit.Event) bool { return e.Tool == "echo" })
	if e.Kind != audit.KindTool || e.Server != "alpha" || e.Decision != "allow" || e.Outcome != audit.OutcomeOK || e.Rule != "eng" || e.RequestID == "" || e.Subject != "key:eng" || e.Auth != "apikey" || e.Instance != "test" {
		t.Errorf("audit record = %+v", e)
	}
}

func TestHiddenLooksMissing(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, internsKey)
	_, hiddenErr := callTool(c, "alpha__echo", nil)
	_, missingErr := callTool(c, "nope__x", nil)
	if hiddenErr == nil || missingErr == nil {
		t.Fatalf("errors = %v, %v", hiddenErr, missingErr)
	}
	hidden := strings.ReplaceAll(hiddenErr.Error(), "alpha__echo", "NAME")
	missing := strings.ReplaceAll(missingErr.Error(), "nope__x", "NAME")
	if hidden != missing {
		t.Errorf("hidden %q differs from missing %q", hidden, missing)
	}
	e := h.sink.find(t, func(e audit.Event) bool { return e.Server == "alpha" && e.Tool == "echo" })
	if e.Outcome != audit.OutcomeDenied || e.Decision != "deny" || e.Rule != rules.DefaultDeny {
		t.Errorf("audit record = %+v", e)
	}
}

func TestToolErrorPassesThrough(t *testing.T) {
	h := newHarness(t)
	res, err := callTool(h.connect(t, engKey), "alpha__fail", nil)
	if err != nil || !res.IsError || text(res) != "failed on purpose" {
		t.Fatalf("alpha__fail = %+v, %v", res, err)
	}
	h.sink.find(t, func(e audit.Event) bool { return e.Tool == "fail" && e.Outcome == audit.OutcomeToolError })
}

func TestNoTokenIs401(t *testing.T) {
	h := newHarness(t)
	for _, key := range []string{"", apikey.Prefix + "wrong"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("key %q: status %d, WWW-Authenticate %q", key, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
}

func TestSessionHijack(t *testing.T) {
	h := newHarness(t)
	//nolint:staticcheck // legacy clients still open sessions, and those must stay bound to their owner
	eng := h.connect(t, engKey, client.WithLegacyProtocolOnly())
	sid := eng.GetSessionId()
	if sid == "" {
		t.Fatal("legacy client has no session ID")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+internsKey)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if names := listNames(t, eng); !slices.Contains(names, "alpha__echo") {
		t.Error("the session's owner lost access")
	}
}

func TestListChangedReachesClient(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, engKey)
	changed := make(chan struct{}, 10)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == mcp.MethodNotificationToolsListChanged {
			changed <- struct{}{}
		}
	})
	stop, err := c.ListenAsync(context.Background(), mcp.SubscriptionFilter{ToolsListChanged: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	waitFor(t, "listen stream open", func() bool {
		select {
		case <-changed:
		default:
		}
		h.gw.Refresh()
		select {
		case <-changed:
			return true
		case <-time.After(20 * time.Millisecond):
			return false
		}
	})
	if _, err := callTool(c, "alpha__add_tool", map[string]any{"name": "new"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha__new listed", func() bool { return slices.Contains(listNames(t, c), "alpha__new") })
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no list_changed after the backend added a tool")
	}
}

func TestBackendDown(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, engKey)
	h.alpha.CloseClientConnections()
	h.alpha.Close()
	start := time.Now()
	res, err := callTool(c, "alpha__echo", map[string]any{"text": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || text(res) != "server alpha is unavailable" || time.Since(start) > 3*time.Second {
		t.Errorf("result = %+v after %v", res, time.Since(start))
	}
	h.sink.find(t, func(e audit.Event) bool { return e.Server == "alpha" && e.Outcome == audit.OutcomeBackendUnavailable })
	if !slices.Contains(listNames(t, c), "alpha__echo") {
		t.Error("alpha__echo no longer listed")
	}
}

func TestConcurrentRefresh(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, engKey)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := callTool(c, "beta__echo", map[string]any{"text": "x"})
			if err == nil && text(res) != "x" {
				err = io.ErrUnexpectedEOF
			}
			errs <- err
		}()
	}
	for i := 0; i < 50; i++ {
		h.gw.Refresh()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNameMapping(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, engKey)
	names := listNames(t, c)
	if !slices.Contains(names, "alpha__a__b") || !slices.Contains(names, "alpha__echo") {
		t.Fatalf("names = %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, " ") {
			t.Errorf("invalid name %q exposed", n)
		}
	}
	res, err := callTool(c, "alpha__a__b", nil)
	if err != nil || text(res) != "a__b" {
		t.Fatalf("alpha__a__b = %v, %v", res, err)
	}
	if !strings.Contains(h.logs.String(), "bad name") {
		t.Error("skipped tool not logged")
	}
}

func TestBadHeaderAnnotationSkipped(t *testing.T) {
	tool := mcp.NewTool("hdr", mcp.WithString("x"))
	tool.InputSchema.Properties["x"] = map[string]any{"type": "string", "x-mcp-header": "Bad Header Name"}
	if _, ok := prefixed("alpha", tool, slog.New(slog.NewTextHandler(io.Discard, nil))); ok {
		t.Error("tool with invalid x-mcp-header kept")
	}
}

func TestStdioDownstream(t *testing.T) {
	h := newHarness(t)
	cIn, gOut := io.Pipe()
	gIn, cOut := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := &auth.Identity{Subject: "local", Groups: []string{"eng"}, Method: "stdio"}
	go func() { _ = h.gw.ServeStdio(ctx, gIn, gOut, id) }()
	c := client.NewClient(transport.NewIO(cIn, cOut, io.NopCloser(strings.NewReader(""))))
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	if names := listNames(t, c); !slices.Contains(names, "alpha__echo") {
		t.Errorf("stdio caller sees %v", names)
	}
}

func TestUnknownSessionRejected(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+engKey)
		req.Header.Set("Mcp-Session-Id", "mcp-session-made-up")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("attempt %d: status = %d, want 403", i, resp.StatusCode)
		}
	}
	if n := h.gw.sessions.len(); n != 0 {
		t.Errorf("%d sessions recorded from a client-supplied header", n)
	}
}

func TestClosedSessionCannotBeReclaimed(t *testing.T) {
	h := newHarness(t)
	//nolint:staticcheck // legacy clients still open sessions
	eng := h.connect(t, engKey, client.WithLegacyProtocolOnly())
	sid := eng.GetSessionId()
	_ = eng.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+internsKey)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func rawRequest(t *testing.T, method, url, key, sid string) int {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, url, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestUnauthenticatedDeleteRefused(t *testing.T) {
	h := newHarness(t)
	//nolint:staticcheck // legacy clients still open sessions
	eng := h.connect(t, engKey, client.WithLegacyProtocolOnly())
	sid := eng.GetSessionId()
	if code := rawRequest(t, http.MethodDelete, h.url, "", sid); code != http.StatusUnauthorized {
		t.Fatalf("DELETE without credentials = %d, want 401", code)
	}
	if code := rawRequest(t, http.MethodDelete, h.url, internsKey, sid); code != http.StatusForbidden {
		t.Fatalf("DELETE by another caller = %d, want 403", code)
	}
	if names := listNames(t, eng); !slices.Contains(names, "alpha__echo") {
		t.Error("session ended by someone who does not own it")
	}
}

func TestOwnerDeleteUnbinds(t *testing.T) {
	h := newHarness(t)
	//nolint:staticcheck // legacy clients still open sessions
	eng := h.connect(t, engKey, client.WithLegacyProtocolOnly())
	sid := eng.GetSessionId()
	if code := rawRequest(t, http.MethodDelete, h.url, engKey, sid); code >= 300 {
		t.Fatalf("owner DELETE = %d", code)
	}
	if h.gw.sessions.known(sid) {
		t.Error("session still bound after its owner ended it")
	}
}
