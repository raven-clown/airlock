// Package telemetry holds airlock's Prometheus metrics and its OTLP tracer. Nothing on a
// label or a span carries a subject, a key, a token or tool arguments.
package telemetry

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Other is the label value for anything outside the known set, such as a tool name the
// catalog does not have.
const Other = overflow

// durationBuckets cover a cached answer in milliseconds up to a slow tool, in seconds.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

// Metrics are airlock's Prometheus metrics. A nil *Metrics records nothing.
type Metrics struct {
	reg *Registry

	requests     *Vec
	duration     *Vec
	inflight     *Vec
	limited      *Vec
	dropped      *Vec
	toolCalls    *Vec
	toolDuration *Vec
	backendUp    *Vec
	authFailures *Vec
	reloads      *Vec
	revision     *Vec

	mu    sync.RWMutex
	known func(server, tool string) bool
}

// NewMetrics returns the metrics, with the build's version as airlock_build_info.
func NewMetrics(version string) *Metrics {
	r := NewRegistry()
	m := &Metrics{
		reg: r,
		requests: r.Counter("airlock_requests_total",
			"HTTP requests answered, by route pattern and status code.", "route", "code"),
		duration: r.Histogram("airlock_request_duration_seconds",
			"Time from a request arriving to the last byte of its answer, by route pattern.", durationBuckets, "route"),
		inflight: r.Gauge("airlock_inflight_requests", "HTTP requests being served now."),
		limited: r.Counter("airlock_limited_total",
			"Requests and tool calls refused by a limit, by the error code of the refusal.", "reason"),
		dropped: r.Counter("airlock_events_dropped_total",
			"Audit records and spans that could not be delivered, by where they were going.", "sink"),
		toolCalls: r.Counter("airlock_tool_calls_total",
			"Tool calls, by server, tool and audit outcome.", "server", "tool", "outcome"),
		toolDuration: r.Histogram("airlock_tool_call_duration_seconds",
			"Time a tool call took, by server.", durationBuckets, "server"),
		backendUp: r.Gauge("airlock_backend_up", "1 when the backend is connected, 0 when not.", "server"),
		authFailures: r.Counter("airlock_auth_failures_total",
			"Credentials refused, by method and reason.", "method", "reason"),
		reloads: r.Counter("airlock_config_reloads_total",
			"Reloads of the config from the store, by result.", "result"),
		revision: r.Gauge("airlock_revision", "The store revision the running config was built from."),
	}
	r.Gauge("airlock_build_info", "The running version, as a label on a constant 1.", "version").Set(1, version)
	// Series without labels exist from the start, so a dashboard shows 0 rather than no data.
	m.inflight.Add(0)
	m.revision.Add(0)
	return m
}

// SetCatalog sets the check for tool labels: a server and tool known says true. Until it is
// set, every tool is counted as other.
func (m *Metrics) SetCatalog(known func(server, tool string) bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known = known
}

func (m *Metrics) toolLabels(server, tool string) (string, string) {
	m.mu.RLock()
	known := m.known
	m.mu.RUnlock()
	if known != nil && known(server, tool) {
		return server, tool
	}
	if known != nil && known(server, "") {
		return server, Other
	}
	return Other, Other
}

// Request counts one finished HTTP request. route is the mux pattern, empty for none.
func (m *Metrics) Request(route string, code int, d time.Duration) {
	if m == nil {
		return
	}
	if route == "" {
		route = Other
	}
	m.requests.Add(1, route, strconv.Itoa(code))
	m.duration.Observe(d.Seconds(), route)
}

// Inflight changes the number of requests being served by delta.
func (m *Metrics) Inflight(delta int) {
	if m != nil {
		m.inflight.Add(float64(delta))
	}
}

// Limited counts a refusal by its error code.
func (m *Metrics) Limited(reason string) {
	if m != nil {
		m.limited.Add(1, reason)
	}
}

// Dropped counts n records or spans lost on the way to sink.
func (m *Metrics) Dropped(sink string, n float64) {
	if m != nil && n > 0 {
		m.dropped.Add(n, sink)
	}
}

// ToolCall counts one tool call. Names outside the catalog are counted as other.
func (m *Metrics) ToolCall(server, tool, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	s, t := m.toolLabels(server, tool)
	m.toolCalls.Add(1, s, t, outcome)
	m.toolDuration.Observe(d.Seconds(), s)
}

// BackendUp sets whether server is connected.
func (m *Metrics) BackendUp(server string, up bool) {
	if m == nil {
		return
	}
	v := 0.0
	if up {
		v = 1
	}
	m.backendUp.Set(v, server)
}

// AuthFailure counts a refused credential. reason is a short fixed code.
func (m *Metrics) AuthFailure(method, reason string) {
	if m != nil {
		m.authFailures.Add(1, method, reason)
	}
}

// Reload counts a reload that was tried.
func (m *Metrics) Reload(ok bool) {
	if m == nil {
		return
	}
	result := "failed"
	if ok {
		result = "ok"
	}
	m.reloads.Add(1, result)
}

// Revision sets the store revision of the running config.
func (m *Metrics) Revision(rev int64) {
	if m != nil {
		m.revision.Set(float64(rev))
	}
}

// Handler serves the metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = m.reg.WriteTo(w)
	})
}

type spanKey struct{}

// WithSpan returns a context carrying s, so the work under it can start child spans.
func WithSpan(ctx context.Context, s *Span) context.Context {
	return context.WithValue(ctx, spanKey{}, s)
}

// SpanFrom returns the span WithSpan stored, or nil.
func SpanFrom(ctx context.Context) *Span {
	s, _ := ctx.Value(spanKey{}).(*Span)
	return s
}
