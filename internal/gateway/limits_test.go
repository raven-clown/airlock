package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/telemetry"
)

func withProfile(lim map[string]any) func(*config.Config) {
	return func(c *config.Config) {
		c.Profiles = []limits.Spec{{Name: "p", Limits: lim}}
		c.Settings.DefaultProfile = "p"
	}
}

func scrape(t *testing.T, m *telemetry.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	return w.Body.String()
}

func TestToolCallRateLimited(t *testing.T) {
	h := newHarnessWith(t, withProfile(map[string]any{"tools.calls": map[string]any{"rate": "1/h"}}))
	c := h.connect(t, engKey)
	if res, err := callTool(c, "alpha__echo", map[string]any{"text": "a"}); err != nil || res.IsError {
		t.Fatalf("first call: %+v, %v", res, err)
	}
	res, err := callTool(c, "alpha__echo", map[string]any{"text": "b"})
	if err != nil || !res.IsError || !strings.HasPrefix(text(res), "rate_limited: tools.calls allows 1/h for key:eng; retry in ") {
		t.Fatalf("second call: %+v (%q), %v", res, text(res), err)
	}
	h.sink.find(t, func(e audit.Event) bool { return e.Outcome == audit.OutcomeRateLimited && e.Tool == "echo" })
	out := scrape(t, h.metrics)
	for _, want := range []string{
		`airlock_limited_total{reason="rate_limited"} 1`,
		`airlock_tool_calls_total{server="alpha",tool="echo",outcome="rate_limited"} 1`,
		`airlock_tool_calls_total{server="alpha",tool="echo",outcome="ok"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if _, err := callTool(h.connect(t, internsKey), "beta__echo", nil); err != nil {
		t.Fatalf("another caller shares the counter: %v", err)
	}
}

func TestToolCallConcurrencyLimited(t *testing.T) {
	h := newHarnessWith(t, withProfile(map[string]any{"tools.calls": map[string]any{"concurrency": 1}}))
	c := h.connect(t, engKey)
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		req := mcp.CallToolRequest{}
		req.Params.Name = "alpha__wait"
		_, err := c.CallTool(ctx, req)
		waiting <- err
	}()
	waitFor(t, "the slow call to start", func() bool {
		return strings.Contains(scrape(t, h.metrics), "airlock_inflight_requests 1")
	})
	res, err := callTool(h.connect(t, engKey), "alpha__echo", nil)
	cancel()
	if err := <-waiting; err == nil {
		t.Error("the canceled call returned no error")
	}
	if err != nil || !res.IsError || !strings.HasPrefix(text(res), "concurrency_limited: ") {
		t.Fatalf("second call: %+v (%q), %v", res, text(res), err)
	}
}

func TestBackendGetsTraceparent(t *testing.T) {
	h := newHarness(t)
	tr, err := transport.NewStreamableHTTP(h.url, transport.WithHTTPHeaders(map[string]string{
		"Authorization": "Bearer " + engKey,
		"Traceparent":   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}))
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(tr)
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(context.Background(), init); err != nil {
		t.Fatal(err)
	}
	if _, err := callTool(c, "alpha__echo", map[string]any{"text": "x"}); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tp := range h.seen.values("Traceparent") {
		sc, ok := telemetry.ParseTraceparent(tp)
		parent, _ := telemetry.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		if ok && sc.TraceID == parent.TraceID && sc.SpanID != parent.SpanID {
			found = true
		}
	}
	if !found {
		t.Fatalf("backend saw traceparents %v, want the caller's trace with airlock's span", h.seen.values("Traceparent"))
	}
}

func TestDeniedCallCounted(t *testing.T) {
	h := newHarness(t)
	c := h.connect(t, internsKey)
	_, _ = callTool(c, "alpha__echo", nil)
	_, _ = callTool(c, "made__up", nil)
	waitFor(t, "denied calls counted", func() bool {
		out := scrape(t, h.metrics)
		return strings.Contains(out, `airlock_tool_calls_total{server="alpha",tool="echo",outcome="denied"} 1`) &&
			strings.Contains(out, `airlock_tool_calls_total{server="other",tool="other",outcome="denied"} 1`)
	})
}

func TestStdioToolCallLimited(t *testing.T) {
	h := newHarnessWith(t, withProfile(map[string]any{"tools.calls": map[string]any{"rate": "1/h"}}))
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
	if _, err := callTool(c, "alpha__echo", nil); err != nil {
		t.Fatal(err)
	}
	callCtx, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	req := mcp.CallToolRequest{}
	req.Params.Name = "alpha__echo"
	res, err := c.CallTool(callCtx, req)
	if err != nil || !res.IsError || !strings.Contains(text(res), "user:local") {
		t.Fatalf("second stdio call: %+v, %v", res, err)
	}
}
