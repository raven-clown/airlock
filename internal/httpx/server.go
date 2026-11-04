package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/raven-clown/airlock/policy/glob"
)

// NewMux routes /mcp, /healthz and /readyz.
func NewMux(mcp http.Handler, ready func() error) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp)
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
