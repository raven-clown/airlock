package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	return rec.Body.String()
}

func TestSharedNames(t *testing.T) {
	m := NewMetrics("v0.2.0")
	m.Request("POST /mcp", 200, 10*time.Millisecond)
	m.Request("", 404, time.Millisecond)
	m.Inflight(1)
	m.Limited("rate_limited")
	m.Dropped("audit", 3)
	m.Dropped("otlp", 0)
	m.AuthFailure("oidc", "expired")
	m.Reload(true)
	m.Reload(false)
	m.Revision(7)
	m.BackendUp("github", true)
	m.BackendUp("files", false)
	out := scrape(t, m)
	for _, want := range []string{
		`airlock_requests_total{route="POST /mcp",code="200"} 1`,
		`airlock_requests_total{route="other",code="404"} 1`,
		`airlock_request_duration_seconds_count{route="POST /mcp"} 1`,
		`airlock_inflight_requests 1`,
		`airlock_limited_total{reason="rate_limited"} 1`,
		`airlock_events_dropped_total{sink="audit"} 3`,
		`airlock_auth_failures_total{method="oidc",reason="expired"} 1`,
		`airlock_config_reloads_total{result="ok"} 1`,
		`airlock_config_reloads_total{result="failed"} 1`,
		`airlock_revision 7`,
		`airlock_backend_up{server="github"} 1`,
		`airlock_backend_up{server="files"} 0`,
		`airlock_build_info{version="v0.2.0"} 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if strings.Contains(out, `sink="otlp"`) {
		t.Error("a drop of zero made a series")
	}
}

func TestToolLabelsBounded(t *testing.T) {
	m := NewMetrics("v")
	m.ToolCall("github", "create_issue", "ok", time.Millisecond)
	m.SetCatalog(func(server, tool string) bool {
		return server == "github" && (tool == "" || tool == "create_issue")
	})
	m.ToolCall("github", "create_issue", "ok", time.Millisecond)
	m.ToolCall("github", "made_up", "denied", time.Millisecond)
	m.ToolCall("nope", "x", "denied", time.Millisecond)
	out := scrape(t, m)
	for _, want := range []string{
		`airlock_tool_calls_total{server="other",tool="other",outcome="ok"} 1`,
		`airlock_tool_calls_total{server="github",tool="create_issue",outcome="ok"} 1`,
		`airlock_tool_calls_total{server="github",tool="other",outcome="denied"} 1`,
		`airlock_tool_calls_total{server="other",tool="other",outcome="denied"} 1`,
		`airlock_tool_call_duration_seconds_count{server="github"} 2`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestNilMetrics(t *testing.T) {
	var m *Metrics
	m.Request("r", 200, 0)
	m.Inflight(1)
	m.Limited("x")
	m.Dropped("s", 1)
	m.ToolCall("a", "b", "ok", 0)
	m.BackendUp("a", true)
	m.AuthFailure("a", "b")
	m.Reload(true)
	m.Revision(1)
	m.SetCatalog(nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestSpanContext(t *testing.T) {
	if SpanFrom(context.Background()) != nil {
		t.Fatal("span from an empty context")
	}
	tr, err := NewTracer(TracerConfig{Exporter: &discard{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()
	s := tr.Start("x", SpanServer, "", "")
	if SpanFrom(WithSpan(context.Background(), s)) != s {
		t.Fatal("span not kept")
	}
}

func TestExportErrorHidesURL(t *testing.T) {
	e := &otlpExporter{url: "http://user:hunter2@127.0.0.1:1/v1/traces?key=hunter2", client: &http.Client{}}
	err := e.Export(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("err = %v", err)
	}
}

type discard struct{}

func (discard) Export(context.Context, []SpanData) error { return nil }
