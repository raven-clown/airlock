package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckOrigin(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	allowed := func() []string { return []string{"http://localhost:*", "https://console.example.com"} }
	tests := []struct {
		origin string
		want   int
	}{
		{"", http.StatusNoContent},
		{"http://localhost:3000", http.StatusNoContent},
		{"https://console.example.com", http.StatusNoContent},
		{"https://evil.example", http.StatusForbidden},
		{"http://localhost.evil.example", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()
			CheckOrigin(allowed, ok).ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestCheckOriginEmptyList(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	CheckOrigin(func() []string { return nil }, ok).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	return w
}

func TestMux(t *testing.T) {
	var readyErr error
	mcp := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	mux := NewMux(mcp, func() error { return readyErr })

	if w := get(t, mux, "/healthz"); w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Errorf("healthz = %d %q", w.Code, w.Body.String())
	}
	if w := get(t, mux, "/mcp"); w.Code != http.StatusTeapot {
		t.Errorf("/mcp = %d", w.Code)
	}

	w := get(t, mux, "/readyz")
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK || body["status"] != "ok" {
		t.Errorf("readyz = %d %s", w.Code, w.Body.String())
	}

	readyErr = errors.New("backend github is not up")
	w = get(t, mux, "/readyz")
	body = nil
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusServiceUnavailable || body["status"] != "unavailable" || body["error"] != "backend github is not up" {
		t.Errorf("readyz = %d %s", w.Code, w.Body.String())
	}
}
