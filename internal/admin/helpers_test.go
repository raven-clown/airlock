package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/gateway"
	"github.com/raven-clown/airlock/internal/httpx"
	"github.com/raven-clown/airlock/internal/provision"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
)

const (
	adminKey  = apikey.Prefix + "test-admin"
	viewerKey = apikey.Prefix + "test-viewer"
	memberKey = apikey.Prefix + "test-member"
	nobodyKey = apikey.Prefix + "test-nobody"
)

// baseDoc declares a key per role, and one with no role.
func baseDoc() string {
	return fmt.Sprintf(`
api_keys:
  - {name: admin, sha256: %s}
  - {name: viewer, sha256: %s}
  - {name: member, sha256: %s, groups: [eng]}
  - {name: nobody, sha256: %s}
role_bindings:
  - {name: admins, subjects: ["key:admin", "group:ops"], role: admin}
  - {name: viewers, subjects: ["key:viewer"], role: viewer}
  - {name: members, subjects: ["key:member"], role: member}
rules:
  - {name: eng, subjects: ["group:eng"], allow: ["github__*"], deny: ["github__delete_*"]}
`, apikey.Hash(adminKey), apikey.Hash(viewerKey), apikey.Hash(memberKey), apikey.Hash(nobodyKey))
}

type fakeCatalog []string

func (c fakeCatalog) Tools() []gateway.Tool {
	out := make([]gateway.Tool, 0, len(c))
	for _, name := range c {
		srv, _, _ := strings.Cut(name, "__")
		out = append(out, gateway.Tool{Name: name, Server: srv, Tool: mcp.Tool{Name: name, Description: "does " + name}})
	}
	return out
}

var catalog = fakeCatalog{"files__read", "github__create_issue", "github__delete_repo"}

type rig struct {
	t        *testing.T
	st       *store.Store
	holder   *runtime.Holder
	reloader *runtime.Reloader
	h        http.Handler
	spec     *spec
}

// newRig serves the admin API over a store provisioned from doc, behind the same front as
// in serve. change edits the process config first.
func newRig(t *testing.T, doc string, change func(*config.Config)) *rig {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.Parse([]byte(doc), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(cfg)
	}
	st, err := store.Open(ctx, "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := provision.Apply(ctx, st, store.DefaultOrg, cfg); err != nil {
		t.Fatal(err)
	}
	src := runtime.NewStoreSource(st, store.DefaultOrg, cfg)
	snap, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	holder := runtime.NewHolder(snap)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloader := runtime.NewReloader(src, holder, runtime.WatchOptions{Logger: log})
	if _, err := reloader.Check(ctx); err != nil {
		t.Fatal(err)
	}
	adm := New(Deps{
		Store: st, Org: store.DefaultOrg, Source: src, Runtime: holder, Reloader: reloader, Catalog: catalog,
		Process: cfg, Logger: log, Version: "test", Instance: "test-1", Started: time.Now().Add(-time.Minute),
	})
	mux := http.NewServeMux()
	mux.Handle(Prefix+"/", httpx.Front(httpx.FrontOptions{Runtime: holder, Logger: log}, adm))
	return &rig{t: t, st: st, holder: holder, reloader: reloader, h: mux, spec: loadSpec(t)}
}

// do sends one request and checks the answer against openapi.yaml. header holds name, value pairs.
func (r *rig) do(method, path, token string, body any, header ...string) *httptest.ResponseRecorder {
	r.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			r.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, Prefix+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		path, _, _ := strings.Cut(path, "?")
		if err := r.spec.checkResponse(method, Prefix+path, w); err != nil {
			r.t.Error(err)
		}
	}
	return w
}

// want fails the test unless w has status, and returns its JSON body.
func want(t *testing.T, w *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body)
	}
	var v map[string]any
	if w.Body.Len() > 0 && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

// wantError fails the test unless w is an error with status, code and field.
func wantError(t *testing.T, w *httptest.ResponseRecorder, status int, code, field string) {
	t.Helper()
	v := want(t, w, status)
	e, _ := v["error"].(map[string]any)
	if e["code"] != code || (field != "" && e["field"] != field) {
		t.Fatalf("error %v, want code %q field %q", e, code, field)
	}
}

func items(t *testing.T, v map[string]any) []map[string]any {
	t.Helper()
	raw, _ := v["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}
