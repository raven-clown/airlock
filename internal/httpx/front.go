package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/telemetry"
)

// MetadataPath is where the RFC 9728 protected resource metadata is served.
const MetadataPath = "/.well-known/oauth-protected-resource"

// FrontOptions are what Front needs.
type FrontOptions struct {
	Runtime  *runtime.Holder
	Metrics  *telemetry.Metrics
	Tracer   *telemetry.Tracer
	Inflight *limits.Inflight
	Logger   *slog.Logger
}

// Front wraps an authenticated endpoint. In order it keeps or makes the request id, starts
// the server span, counts the request, refuses it past max_inflight, signs the caller in,
// and admits it against the requests limit. next gets the identity and the span in its
// context. The route label is the pattern of the mux that serves the request.
func Front(o FrontOptions, next http.Handler) http.Handler {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Header.Get("X-Request-Id") == "" {
			r.Header.Set("X-Request-Id", NewRequestID())
		}
		reqID := r.Header.Get("X-Request-Id")
		w.Header().Set("X-Request-Id", reqID)
		span := o.Tracer.Start(r.Method+" "+r.URL.Path, telemetry.SpanServer, r.Header.Get("Traceparent"), r.Header.Get("Tracestate"))
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		o.Metrics.Inflight(1)
		defer func() {
			o.Metrics.Inflight(-1)
			o.Metrics.Request(r.Pattern, rec.code, time.Since(start))
			if r.Pattern != "" {
				span.SetName(r.Pattern)
			}
			span.SetInt("http.response.status_code", int64(rec.code))
			if rec.code >= 500 {
				span.Fail("server error")
			}
			span.End()
		}()
		ctx := telemetry.WithSpan(r.Context(), span)
		r = r.WithContext(ctx)

		if o.Inflight != nil {
			release, ok := o.Inflight.Enter()
			if !ok {
				o.Metrics.Limited(limits.CodeOverloaded)
				rec.Header().Set("Retry-After", "1")
				WriteError(rec, http.StatusServiceUnavailable, limits.CodeOverloaded, "airlock is serving as many requests as it may; retry shortly")
				return
			}
			defer release()
		}

		snap := o.Runtime.Current()
		id, err := snap.Authenticator.Authenticate(ctx, r)
		if err != nil {
			refuse(rec, r, snap, o.Metrics, log, err)
			return
		}
		ticket, denied := snap.Limits.Request(ctx, runtime.Caller(id))
		if denied != nil {
			o.Metrics.Limited(denied.Code)
			denied.SetHeaders(rec.Header())
			WriteError(rec, denied.Status, denied.Code, denied.Message)
			return
		}
		defer ticket.Release()
		ticket.SetHeaders(rec.Header())
		next.ServeHTTP(rec, r.WithContext(auth.WithIdentity(ctx, id)))
	})
}

func refuse(w http.ResponseWriter, r *http.Request, snap *runtime.Snapshot, m *telemetry.Metrics, log *slog.Logger, err error) {
	reqID := r.Header.Get("X-Request-Id")
	var inv *auth.InvalidError
	switch {
	case errors.Is(err, auth.ErrUnavailable):
		m.AuthFailure("oidc", "unavailable")
		log.Warn("checking a token", "error", err, "request_id", reqID)
		w.Header().Set("Retry-After", "10")
		WriteError(w, http.StatusServiceUnavailable, "auth_unavailable", "the identity provider could not be reached to check the token")
		return
	case errors.As(err, &inv):
		m.AuthFailure(inv.Method, inv.Reason)
	default:
		m.AuthFailure("none", "missing")
	}
	log.Info("authentication failed", "error", err, "request_id", reqID)
	challenge := `Bearer realm="airlock"`
	if snap.OIDC != nil {
		challenge = `Bearer resource_metadata="` + BaseURL(r, snap.Settings.PublicURL) + MetadataPath + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	WriteError(w, http.StatusUnauthorized, "unauthorized", "a valid API key or token is required")
}

// BaseURL is where clients reach airlock: public when set, else the request's scheme and host.
func BaseURL(r *http.Request, public string) string {
	if public != "" {
		return strings.TrimSuffix(public, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// ResourceMetadata serves the protected resource metadata that MCP clients use to find
// the identity provider, from the current settings. Without OIDC there is none.
func ResourceMetadata(h *runtime.Holder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := h.Current()
		if snap.OIDC == nil {
			http.NotFound(w, r)
			return
		}
		base := BaseURL(r, snap.Settings.PublicURL)
		server.NewProtectedResourceMetadataHandler(server.ProtectedResourceMetadataConfig{
			Resource:               base + "/mcp",
			AuthorizationServers:   []string{snap.OIDC.Issuer()},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "airlock",
		}).ServeHTTP(w, r)
	})
}

// WriteError writes the shared error shape, {"error": {"code", "message"}}.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// NewRequestID returns a random request id.
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recorder keeps the status code. It passes Flush through, since MCP streams need it.
type recorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.written {
		r.code, r.written = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Flush() {
	r.written = true
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
