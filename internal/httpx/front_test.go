package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/auth/oidc/oidctest"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/telemetry"
)

const testKey = apikey.Prefix + "front"

func holder(t *testing.T, change func(*config.Config)) *runtime.Holder {
	t.Helper()
	cfg := config.Default()
	cfg.APIKeys = []apikey.Key{{Name: "front", SHA256: apikey.Hash(testKey), Groups: []string{"eng"}}}
	if change != nil {
		change(cfg)
	}
	snap, err := runtime.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.NewHolder(snap)
}

type spans struct {
	mu  sync.Mutex
	all []telemetry.SpanData
}

func (s *spans) Export(_ context.Context, b []telemetry.SpanData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = append(s.all, b...)
	return nil
}

type frontRig struct {
	mux     *http.ServeMux
	metrics *telemetry.Metrics
	tracer  *telemetry.Tracer
	spans   *spans
	seen    chan *auth.Identity
}

func newRig(t *testing.T, h *runtime.Holder, inflight *limits.Inflight, next http.Handler) *frontRig {
	t.Helper()
	r := &frontRig{metrics: telemetry.NewMetrics("test"), spans: &spans{}, seen: make(chan *auth.Identity, 10)}
	tr, err := telemetry.NewTracer(telemetry.TracerConfig{Exporter: r.spans})
	if err != nil {
		t.Fatal(err)
	}
	r.tracer = tr
	t.Cleanup(func() { _ = tr.Shutdown(context.Background()) })
	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id, _ := auth.FromContext(req.Context())
			r.seen <- id
			if telemetry.SpanFrom(req.Context()) == nil {
				t.Error("no span in the context")
			}
			w.WriteHeader(http.StatusTeapot)
		})
	}
	r.mux = http.NewServeMux()
	r.mux.Handle("POST /x", Front(FrontOptions{Runtime: h, Metrics: r.metrics, Tracer: tr, Inflight: inflight}, next))
	return r
}

func (r *frontRig) do(t *testing.T, token string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://airlock.test/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return body.Error.Code
}

func scrape(t *testing.T, m *telemetry.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	return w.Body.String()
}

func TestFrontSignsIn(t *testing.T) {
	r := newRig(t, holder(t, nil), nil, nil)
	w := r.do(t, testKey, http.Header{"X-Request-Id": {"req-1"}})
	if w.Code != http.StatusTeapot || w.Header().Get("X-Request-Id") != "req-1" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if id := <-r.seen; id.Subject != "key:front" {
		t.Fatalf("identity %+v", id)
	}
	if w := r.do(t, testKey, nil); len(w.Header().Get("X-Request-Id")) != 32 {
		t.Fatalf("no request id made: %v", w.Header())
	}
	if out := scrape(t, r.metrics); !strings.Contains(out, `airlock_requests_total{route="POST /x",code="418"} 2`) {
		t.Fatalf("metrics\n%s", out)
	}
}

func TestFrontRefuses(t *testing.T) {
	r := newRig(t, holder(t, nil), nil, nil)
	tests := []struct {
		name, token, reason string
	}{
		{"missing", "", `method="none",reason="missing"`},
		{"unknown key", apikey.Prefix + "nope", `method="apikey",reason="unknown"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := r.do(t, tc.token, nil)
			if w.Code != http.StatusUnauthorized || errorCode(t, w) != "unauthorized" || w.Header().Get("WWW-Authenticate") != `Bearer realm="airlock"` {
				t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
			}
			if out := scrape(t, r.metrics); !strings.Contains(out, "airlock_auth_failures_total{"+tc.reason+"} 1") {
				t.Fatalf("metrics\n%s", out)
			}
		})
	}
}

func TestFrontOIDCChallenge(t *testing.T) {
	p := oidctest.New(t)
	h := holder(t, func(c *config.Config) {
		c.Settings.OIDC = &config.OIDC{Issuer: p.URL(), Audience: oidctest.Audience}
	})
	r := newRig(t, h, nil, nil)
	w := r.do(t, "", nil)
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer resource_metadata="http://airlock.test/.well-known/oauth-protected-resource"` {
		t.Fatalf("challenge %q", got)
	}
	w = r.do(t, p.Token(p.Claims()), nil)
	if w.Code != http.StatusTeapot {
		t.Fatalf("OIDC token refused: %d %s", w.Code, w.Body)
	}
	if id := <-r.seen; id.Subject != "alice@example.com" || id.Method != "oidc" {
		t.Fatalf("identity %+v", id)
	}

	public := holder(t, func(c *config.Config) {
		c.Settings.OIDC = &config.OIDC{Issuer: p.URL(), Audience: oidctest.Audience}
		c.Settings.PublicURL = "https://airlock.example.com/"
	})
	w = newRig(t, public, nil, nil).do(t, "", nil)
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, `"https://airlock.example.com/.well-known/oauth-protected-resource"`) {
		t.Fatalf("challenge %q", got)
	}
}

func TestFrontIssuerDown(t *testing.T) {
	p := oidctest.New(t)
	tok := p.Token(p.Claims())
	p.SetStatus(http.StatusBadGateway)
	h := holder(t, func(c *config.Config) {
		c.Settings.OIDC = &config.OIDC{Issuer: p.URL(), Audience: oidctest.Audience}
	})
	w := newRig(t, h, nil, nil).do(t, tok, nil)
	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "auth_unavailable" || w.Header().Get("Retry-After") != "10" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestFrontRequestsLimit(t *testing.T) {
	h := holder(t, func(c *config.Config) {
		c.Profiles = []limits.Spec{{Name: "p", Limits: map[string]any{"requests": map[string]any{"rate": "1/m"}}}}
		c.Settings.DefaultProfile = "p"
	})
	r := newRig(t, h, nil, nil)
	w := r.do(t, testKey, nil)
	if w.Code != http.StatusTeapot || w.Header().Get("RateLimit-Policy") != `"requests";q=1;w=60` || !strings.HasPrefix(w.Header().Get("RateLimit"), `"requests";r=0;`) {
		t.Fatalf("first: %d %v", w.Code, w.Header())
	}
	<-r.seen
	w = r.do(t, testKey, nil)
	if w.Code != http.StatusTooManyRequests || errorCode(t, w) != "rate_limited" || w.Header().Get("Retry-After") == "" || w.Header().Get("RateLimit") == "" {
		t.Fatalf("second: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if out := scrape(t, r.metrics); !strings.Contains(out, `airlock_limited_total{reason="rate_limited"} 1`) {
		t.Fatalf("metrics\n%s", out)
	}
}

func TestFrontMaxInflight(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
	})
	r := newRig(t, holder(t, nil), limits.NewInflight(1), slow)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.do(t, testKey, nil)
	}()
	<-entered
	w := r.do(t, testKey, nil)
	close(release)
	<-done
	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "overloaded" || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestFrontSpan(t *testing.T) {
	r := newRig(t, holder(t, nil), nil, nil)
	parent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	r.do(t, testKey, http.Header{"Traceparent": {parent}})
	<-r.seen
	if err := r.tracer.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.spans.mu.Lock()
	defer r.spans.mu.Unlock()
	if len(r.spans.all) != 1 {
		t.Fatalf("%d spans", len(r.spans.all))
	}
	s := r.spans.all[0]
	sc, _ := telemetry.ParseTraceparent(parent)
	if s.Name != "POST /x" || s.TraceID != sc.TraceID || s.ParentID != sc.SpanID || s.Kind != telemetry.SpanServer {
		t.Fatalf("span %+v", s)
	}
}

func TestResourceMetadata(t *testing.T) {
	w := httptest.NewRecorder()
	ResourceMetadata(holder(t, nil)).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, MetadataPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("without OIDC: %d", w.Code)
	}
	h := holder(t, func(c *config.Config) {
		c.Settings.OIDC = &config.OIDC{Issuer: "https://idp.example.com", Audience: "airlock"}
	})
	mux := NewMux(Routes{Metadata: ResourceMetadata(h)})
	for _, path := range []string{MetadataPath, MetadataPath + "/mcp"} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://gw.test"+path, nil))
		var doc struct {
			Resource string   `json:"resource"`
			Servers  []string `json:"authorization_servers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Resource != "http://gw.test/mcp" || len(doc.Servers) != 1 || doc.Servers[0] != "https://idp.example.com" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}
