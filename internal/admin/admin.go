// Package admin serves the JSON admin API under /admin/v1/, as api/openapi.yaml describes it.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/raven-clown/airlock/api"
	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/gateway"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/telemetry"
)

// Prefix is where the admin API is served.
const Prefix = "/admin/v1"

const maxBodyBytes = 1 << 20

// Catalog is the gateway's tool list.
type Catalog interface {
	Tools() []gateway.Tool
}

// Deps are what the admin API needs.
type Deps struct {
	Store    *store.Store
	Org      string
	Source   *runtime.StoreSource
	Runtime  *runtime.Holder
	Reloader *runtime.Reloader
	Catalog  Catalog
	Backends *backend.Set
	// Process is the loaded config file, for the storage driver and stdio.allowed_commands.
	Process  *config.Config
	Logger   *slog.Logger
	Now      func() time.Time
	Version  string
	Instance string
	Started  time.Time
}

type handler struct {
	d   Deps
	mux *http.ServeMux
}

// route is one endpoint and the role its caller needs.
type route struct {
	method, path string
	need         string
	fn           http.HandlerFunc
}

// New returns the handler for every path under Prefix. It expects httpx.Front around it to
// sign the caller in.
func New(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Org == "" {
		d.Org = store.DefaultOrg
	}
	h := &handler{d: d, mux: http.NewServeMux()}
	for _, rt := range h.routes() {
		h.mux.Handle(rt.method+" "+Prefix+rt.path, h.guard(rt.need, rt.fn))
	}
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "", "no such endpoint")
	})
	return h.mux
}

func (h *handler) routes() []route {
	member := func(method, path string, fn http.HandlerFunc) route {
		return route{method, path, config.RoleMember, fn}
	}
	viewer := func(method, path string, fn http.HandlerFunc) route {
		return route{method, path, config.RoleViewer, fn}
	}
	admin := func(method, path string, fn http.HandlerFunc) route { return route{method, path, config.RoleAdmin, fn} }
	routes := []route{
		viewer(http.MethodGet, "/openapi.yaml", h.openapi),
		viewer(http.MethodGet, "/status", h.status),
		viewer(http.MethodGet, "/tools", h.tools),
		viewer(http.MethodPost, "/check", h.check),
		member(http.MethodGet, "/me", h.me),
		member(http.MethodGet, "/me/tools", h.myTools),
		member(http.MethodGet, "/audit", h.audit),
		viewer(http.MethodGet, "/settings", h.getSettings),
		admin(http.MethodPatch, "/settings", h.patchSettings),
		admin(http.MethodPost, "/api-keys", h.createKey),
		admin(http.MethodPost, "/api-keys/{name}/revoke", h.revokeKey),
	}
	for _, k := range h.kinds() {
		base, one := "/"+k.path, "/"+k.path+"/{name}"
		routes = append(routes,
			viewer(http.MethodGet, base, h.list(k)),
			viewer(http.MethodGet, one, h.get(k)),
			admin(http.MethodPatch, one, h.patch(k)),
			admin(http.MethodDelete, one, h.remove(k)),
		)
		if k.path != "api-keys" {
			routes = append(routes, admin(http.MethodPost, base, h.create(k)))
		}
	}
	return routes
}

// guard refuses a caller whose role is below need.
func (h *handler) guard(need string, fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "", "a valid API key or token is required")
			return
		}
		if !runtime.HasRole(h.d.Runtime.Current().Role(id), need) {
			writeError(w, http.StatusForbidden, "forbidden", "", "this needs the "+need+" role, and no role binding gives it to "+id.Subject)
			return
		}
		fn(w, r)
	})
}

func (h *handler) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(api.OpenAPI)
}

// apiError is an error the handler answers with as it is.
type apiError struct {
	status      int
	code, field string
	message     string
}

func (e *apiError) Error() string { return e.message }

func invalid(field, format string, args ...any) *apiError {
	return &apiError{status: http.StatusBadRequest, code: "invalid", field: field, message: fmt.Sprintf(format, args...)}
}

func conflict(code, field, format string, args ...any) *apiError {
	return &apiError{status: http.StatusConflict, code: code, field: field, message: fmt.Sprintf(format, args...)}
}

// fail answers with err: an apiError as it is, a store error with its status, anything else
// as a logged 500.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		writeError(w, ae.status, ae.code, ae.field, ae.message)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "", what+" not found")
	case errors.Is(err, store.ErrVersionConflict):
		writeError(w, http.StatusConflict, "version_conflict", "If-Match", what+" was changed by someone else; read it again and retry")
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "already_exists", "name", what+" already exists")
	case errors.Is(err, store.ErrManagedByFile):
		writeError(w, http.StatusConflict, "managed_by_file", "", what+" is managed by the config file; change it there")
	default:
		h.d.Logger.ErrorContext(r.Context(), "admin request failed", "what", what, "error", err, "request_id", r.Header.Get("X-Request-Id"))
		writeError(w, http.StatusInternalServerError, "internal", "", "the request could not be completed")
	}
}

func writeError(w http.ResponseWriter, status int, code, field, message string) {
	body := map[string]any{"code": code, "message": message}
	if field != "" {
		body["field"] = field
	}
	writeJSON(w, status, map[string]any{"error": body})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeVersioned writes one resource with its version as the ETag.
func writeVersioned(w http.ResponseWriter, status int, version int64, v any) {
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(version, 10)))
	writeJSON(w, status, v)
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return nil, &apiError{status: http.StatusRequestEntityTooLarge, code: "body_too_large", message: "the body is larger than 1 MiB"}
	case err != nil:
		return nil, invalid("", "could not read the body: %v", err)
	}
	return raw, nil
}

// decodeStrict reads one JSON object into dst, refusing unknown fields and naming the field
// that is wrong.
func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil {
		if dec.Decode(&struct{}{}) != io.EOF {
			return invalid("", "the body must hold one JSON object")
		}
		return nil
	}
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &typeErr):
		return invalid(typeErr.Field, "%s must be a JSON %s", typeErr.Field, jsonType(typeErr.Type.Kind().String()))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return invalid(field, "unknown field %s", field)
	case errors.Is(err, io.EOF):
		return invalid("", "the body is empty; send a JSON object")
	}
	return invalid("", "the body is not valid JSON: %v", err)
}

func jsonType(kind string) string {
	switch kind {
	case "string":
		return "string"
	case "bool":
		return "boolean"
	case "slice", "array":
		return "array"
	case "map", "struct", "ptr":
		return "object"
	}
	return "number"
}

// ifMatch returns the version in If-Match, or zero when the header is absent.
func ifMatch(r *http.Request) (int64, error) {
	n, present, err := ifMatchFrom(r, 1)
	if !present {
		return 0, err
	}
	return n, err
}

// ifMatchFrom reads If-Match, which must be at least lowest, and reports whether it was sent.
func ifMatchFrom(r *http.Request, lowest int64) (int64, bool, error) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		return 0, false, nil
	}
	v := strings.Trim(strings.TrimPrefix(raw, "W/"), `"`)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lowest {
		return 0, true, invalid("If-Match", "If-Match must be a resource version such as \"3\", not %q", raw)
	}
	return n, true, nil
}

var (
	itemField    = regexp.MustCompile(`^[a-z_]+\[\d+\]\.([a-z_.]+): `)
	settingField = regexp.MustCompile(`^settings\.([a-z_.]+): `)
	profileField = regexp.MustCompile(`^profiles\[\d+\]: profile "[^"]*": ([a-z_.]+): `)
)

// configError turns the check of the whole config into the answer for a write. A message
// that names a field of the item becomes 400 invalid with that field; anything else is
// invalid_config.
func configError(err error, write bool) error {
	msg := err.Error()
	if write {
		for _, re := range []*regexp.Regexp{itemField, settingField} {
			if m := re.FindStringSubmatch(msg); m != nil {
				return invalid(m[1], "%s", msg)
			}
		}
		if m := profileField.FindStringSubmatch(msg); m != nil {
			return invalid("limits."+m[1], "%s", msg)
		}
		if strings.HasPrefix(msg, "rules: ") && strings.Contains(msg, "subject") {
			return invalid("subjects", "%s", strings.TrimPrefix(msg, "rules: "))
		}
	}
	return &apiError{status: http.StatusBadRequest, code: "invalid_config", message: "the change would leave a config that does not load: " + msg}
}

// event is the audit record of an admin write by the caller of r.
func (h *handler) event(r *http.Request, action, resource string) audit.Event {
	e := audit.Event{
		Time:      h.d.Now().UTC(),
		Kind:      audit.KindAdmin,
		Action:    action,
		Resource:  resource,
		Route:     r.Pattern,
		RequestID: r.Header.Get("X-Request-Id"),
		Instance:  h.d.Instance,
		Outcome:   audit.OutcomeOK,
	}
	if s := telemetry.SpanFrom(r.Context()); s != nil {
		if sc := s.Context(); sc.Valid() {
			e.TraceID = fmt.Sprintf("%x", sc.TraceID)
		}
	}
	if id, ok := auth.FromContext(r.Context()); ok {
		e.Subject, e.Groups, e.Auth = id.Subject, id.Groups, id.Method
	}
	return e
}

// reload makes a committed write live on this instance before the answer. A config that fails
// to load keeps the old one serving and shows in /status; the write itself has committed.
func (h *handler) reload(r *http.Request) {
	if h.d.Reloader == nil {
		return
	}
	if _, err := h.d.Reloader.Check(context.WithoutCancel(r.Context())); err != nil {
		h.d.Logger.WarnContext(r.Context(), "reloading after an admin write", "error", err)
	}
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
