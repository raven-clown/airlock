package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/raven-clown/airlock/policy/glob"
)

// Routes are the handlers NewMux serves. A nil handler is left out.
type Routes struct {
	MCP      http.Handler
	Admin    http.Handler
	Metrics  http.Handler
	Metadata http.Handler
	Ready    func() error
}

// NewMux routes /mcp, /admin/v1/, /metrics, the protected resource metadata, /healthz and /readyz.
func NewMux(rt Routes) *http.ServeMux {
	mux := http.NewServeMux()
	ready := rt.Ready
	if ready == nil {
		ready = func() error { return nil }
	}
	if rt.MCP != nil {
		mux.Handle("/mcp", rt.MCP)
	}
	if rt.Admin != nil {
		mux.Handle("/admin/v1/", rt.Admin)
	}
	if rt.Metrics != nil {
		mux.Handle("GET /metrics", rt.Metrics)
	}
	if rt.Metadata != nil {
		// Clients look for the document at the root and with the resource's path appended.
		mux.Handle(MetadataPath, rt.Metadata)
		mux.Handle(MetadataPath+"/mcp", rt.Metadata)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]string{"status": "ok"}
		if err := ready(); err != nil {
			body = map[string]string{"status": "unavailable", "error": err.Error()}
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	return mux
}

// CheckOrigin rejects requests whose Origin header matches none of the allowed globs.
// Requests without an Origin, which is what non-browser clients send, pass.
func CheckOrigin(allowed func() []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		for _, pat := range allowed() {
			if glob.Match(pat, origin) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "origin not allowed", http.StatusForbidden)
	})
}
