package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/oidc/oidctest"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/policy"
)

func TestRoles(t *testing.T) {
	p := oidctest.New(t)
	doc := baseDoc() + fmt.Sprintf("settings:\n  oidc: {issuer: %q, audience: %s}\n", p.URL(), oidctest.Audience)
	r := newRig(t, doc, nil)
	opsClaims := p.Claims()
	opsClaims["groups"] = []string{"ops"}
	ops := p.Token(opsClaims)
	guestClaims := p.Claims()
	guestClaims["groups"] = []string{"guests"}
	rule := map[string]any{"name": "x", "subjects": []string{"*"}}
	tests := []struct {
		name, token, method, path string
		body                      any
		status                    int
	}{
		{"no credentials", "", http.MethodGet, "/me", nil, http.StatusUnauthorized},
		{"no role", nobodyKey, http.MethodGet, "/me", nil, http.StatusForbidden},
		{"member reads me", memberKey, http.MethodGet, "/me", nil, http.StatusOK},
		{"member reads own audit", memberKey, http.MethodGet, "/audit", nil, http.StatusOK},
		{"member cannot read status", memberKey, http.MethodGet, "/status", nil, http.StatusForbidden},
		{"member cannot check", memberKey, http.MethodPost, "/check", map[string]any{"user": "a"}, http.StatusForbidden},
		{"viewer reads status", viewerKey, http.MethodGet, "/status", nil, http.StatusOK},
		{"viewer checks", viewerKey, http.MethodPost, "/check", map[string]any{"user": "a"}, http.StatusOK},
		{"viewer cannot write", viewerKey, http.MethodPost, "/rules", rule, http.StatusForbidden},
		{"admin writes", adminKey, http.MethodPost, "/rules", rule, http.StatusCreated},
		{"OIDC user in an admin group", ops, http.MethodDelete, "/rules/x", nil, http.StatusNoContent},
		{"OIDC user without a binding", p.Token(guestClaims), http.MethodGet, "/me", nil, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := r.do(tc.method, tc.path, tc.token, tc.body)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body)
			}
		})
	}
}

func TestRuleCRUD(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	created := want(t, r.do(http.MethodPost, "/rules", adminKey, map[string]any{"name": "ci", "subjects": []string{"key:ci"}, "allow": []string{"github__create_*"}}), http.StatusCreated)
	v1, _ := created["version"].(float64)
	if v1 < 1 || created["source"] != "api" || created["managed_by_file"] != false {
		t.Fatalf("created %v", created)
	}
	etag := func(v float64) string { return fmt.Sprintf(`"%d"`, int64(v)) }
	wantError(t, r.do(http.MethodPost, "/rules", adminKey, map[string]any{"name": "ci", "subjects": []string{"*"}}), http.StatusConflict, "already_exists", "name")

	w := r.do(http.MethodGet, "/rules/ci", viewerKey, nil)
	want(t, w, http.StatusOK)
	if w.Header().Get("ETag") != etag(v1) {
		t.Fatalf("ETag %q, want %s", w.Header().Get("ETag"), etag(v1))
	}
	patched := want(t, r.do(http.MethodPatch, "/rules/ci", adminKey, map[string]any{"deny": []string{"github__create_repo"}}, "If-Match", etag(v1)), http.StatusOK)
	if patched["version"] != v1+1 || len(patched["allow"].([]any)) != 1 || len(patched["deny"].([]any)) != 1 {
		t.Fatalf("patched %v", patched)
	}
	wantError(t, r.do(http.MethodPatch, "/rules/ci", adminKey, map[string]any{"deny": nil}, "If-Match", etag(v1)), http.StatusConflict, "version_conflict", "If-Match")
	wantError(t, r.do(http.MethodPatch, "/rules/ci", adminKey, map[string]any{"name": "other"}), http.StatusBadRequest, "invalid", "name")
	wantError(t, r.do(http.MethodDelete, "/rules/ci", adminKey, nil, "If-Match", "three"), http.StatusBadRequest, "invalid", "If-Match")
	want(t, r.do(http.MethodDelete, "/rules/ci", adminKey, nil, "If-Match", etag(v1+1)), http.StatusNoContent)
	wantError(t, r.do(http.MethodGet, "/rules/ci", adminKey, nil), http.StatusNotFound, "not_found", "")

	events, err := r.st.ListAudit(context.Background(), store.DefaultOrg, store.AuditQuery{Kind: audit.KindAdmin})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.Action+" "+e.Resource+" "+e.Route+" "+e.Subject)
	}
	wantEvents := []string{
		"delete rules/ci DELETE /admin/v1/rules/{name} key:admin",
		"update rules/ci PATCH /admin/v1/rules/{name} key:admin",
		"create rules/ci POST /admin/v1/rules key:admin",
	}
	if strings.Join(got, "\n") != strings.Join(wantEvents, "\n") {
		t.Fatalf("audit records\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantEvents, "\n"))
	}
}

func TestWriteIsLiveAtOnce(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	want(t, r.do(http.MethodPost, "/rules", adminKey, map[string]any{"name": "files", "subjects": []string{"key:viewer"}, "allow": []string{"files__*"}}), http.StatusCreated)
	snap := r.holder.Current()
	d := snap.Policy.Decide(context.Background(), policy.Request{Identity: identity("key:viewer", "viewer"), Tool: "files__read"})
	if !d.Allow || d.Rule != "files" {
		t.Fatalf("the new rule is not live: %+v", d)
	}
}

func TestInvalidWritesStoreNothing(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	tests := []struct {
		name, path  string
		body        any
		code, field string
	}{
		{"rule without subjects", "/rules", map[string]any{"name": "r"}, "invalid", "subjects"},
		{"unknown field", "/rules", map[string]any{"name": "r", "subjects": []string{"*"}, "colour": "red"}, "invalid", "colour"},
		{"wrong type", "/rules", map[string]any{"name": "r", "subjects": "everyone"}, "invalid", "subjects"},
		{"bad subject", "/rules", map[string]any{"name": "r", "subjects": []string{"team:x"}}, "invalid", "subjects"},
		{"no name", "/role-bindings", map[string]any{"subjects": []string{"*"}, "role": "viewer"}, "invalid", "name"},
		{"bad role", "/role-bindings", map[string]any{"name": "b", "subjects": []string{"*"}, "role": "owner"}, "invalid", "role"},
		{"bad rate", "/profiles", map[string]any{"name": "p", "limits": map[string]any{"requests": map[string]any{"rate": "fast"}}}, "invalid", "limits.requests"},
		{"unknown limit", "/profiles", map[string]any{"name": "p", "limits": map[string]any{"tools.bytes": 1}}, "invalid_config", ""},
		{"binding to no profile", "/profile-bindings", map[string]any{"name": "b", "subject": "user:a", "profile": "gold"}, "invalid", "profile"},
		{"not JSON", "/rules", "{", "invalid", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantError(t, r.do(http.MethodPost, tc.path, adminKey, tc.body), http.StatusBadRequest, tc.code, tc.field)
		})
	}
	for _, k := range []store.Kind{store.KindRules, store.KindProfiles, store.KindProfileBindings} {
		rows, _ := r.st.List(context.Background(), store.DefaultOrg, k, "", 0)
		for _, row := range rows {
			if row.Source == store.SourceAPI {
				t.Errorf("%s %s was stored", k, row.Name)
			}
		}
	}
	events, _ := r.st.ListAudit(context.Background(), store.DefaultOrg, store.AuditQuery{Kind: audit.KindAdmin})
	if len(events) != 0 {
		t.Fatalf("%d audit records for refused writes", len(events))
	}
}

func TestDeleteInUse(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	want(t, r.do(http.MethodPost, "/profiles", adminKey, map[string]any{"name": "free", "limits": map[string]any{"tools.calls": map[string]any{"rate": "30/m"}}}), http.StatusCreated)
	want(t, r.do(http.MethodPost, "/profile-bindings", adminKey, map[string]any{"name": "b", "subject": "group:eng", "profile": "free"}), http.StatusCreated)
	wantError(t, r.do(http.MethodDelete, "/profiles/free", adminKey, nil), http.StatusBadRequest, "invalid_config", "")
	want(t, r.do(http.MethodDelete, "/profile-bindings/b", adminKey, nil), http.StatusNoContent)
	want(t, r.do(http.MethodDelete, "/profiles/free", adminKey, nil), http.StatusNoContent)
}

func TestManagedByFile(t *testing.T) {
	r := newRig(t, baseDoc()+"settings:\n  allowed_origins: [\"http://localhost:*\"]\n", nil)
	got := want(t, r.do(http.MethodGet, "/rules/eng", viewerKey, nil), http.StatusOK)
	if got["managed_by_file"] != true || got["source"] != "file" {
		t.Fatalf("file rule %v", got)
	}
	wantError(t, r.do(http.MethodPatch, "/rules/eng", adminKey, map[string]any{"deny": nil}), http.StatusConflict, "managed_by_file", "")
	wantError(t, r.do(http.MethodDelete, "/rules/eng", adminKey, nil), http.StatusConflict, "managed_by_file", "")
	wantError(t, r.do(http.MethodPost, "/api-keys/admin/revoke", adminKey, nil), http.StatusConflict, "managed_by_file", "")
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"allowed_origins": []string{"*"}}), http.StatusConflict, "managed_by_file", "allowed_origins")
	wantError(t, r.do(http.MethodPost, "/rules", adminKey, map[string]any{"name": "eng", "subjects": []string{"*"}}), http.StatusConflict, "already_exists", "name")
}

func TestPagination(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	for i := range 120 {
		spec := fmt.Sprintf(`{"name":"r%03d","subjects":["*"]}`, i)
		if _, err := r.st.Create(context.Background(), store.DefaultOrg, store.KindRules, fmt.Sprintf("r%03d", i), []byte(spec)); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	path := "/rules"
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("too many pages")
		}
		v := want(t, r.do(http.MethodGet, path, viewerKey, nil), http.StatusOK)
		for _, it := range items(t, v) {
			names = append(names, it["name"].(string))
		}
		next, ok := v["next_cursor"].(string)
		if !ok {
			break
		}
		path = "/rules?cursor=" + next
	}
	if len(names) != 121 || names[0] != "eng" || names[120] != "r119" {
		t.Fatalf("%d names: first %v last %v", len(names), names[0], names[len(names)-1])
	}
	v := want(t, r.do(http.MethodGet, "/rules?limit=500", viewerKey, nil), http.StatusOK)
	if len(items(t, v)) != 121 || v["next_cursor"] != nil {
		t.Fatalf("one big page: %d items, cursor %v", len(items(t, v)), v["next_cursor"])
	}
	wantError(t, r.do(http.MethodGet, "/rules?limit=501", viewerKey, nil), http.StatusBadRequest, "invalid", "limit")
	wantError(t, r.do(http.MethodGet, "/rules?cursor=!!", viewerKey, nil), http.StatusBadRequest, "invalid", "cursor")
}

func TestServers(t *testing.T) {
	r := newRig(t, baseDoc(), func(c *config.Config) { c.Stdio.AllowedCommands = []string{"mcp-*"} })
	stdio := map[string]any{"name": "gh", "transport": "stdio", "command": "mcp-github", "args": []string{"stdio"},
		"env": map[string]string{"GITHUB_TOKEN": "${GH_TOKEN}"}, "call_timeout": "30s"} //nolint:gosec // a reference, not a secret
	got := want(t, r.do(http.MethodPost, "/servers", adminKey, stdio), http.StatusCreated)
	if got["call_timeout"] != "30s" || got["env"].(map[string]any)["GITHUB_TOKEN"].(map[string]any)["ref"] != "${GH_TOKEN}" {
		t.Fatalf("created %v", got)
	}
	httpServer := map[string]any{"name": "logbook", "transport": "streamable_http", "url": "http://logbook:8420/mcp",
		"auth": map[string]any{"mode": "static", "headers": map[string]string{"Authorization": "Bearer ${LOGBOOK_KEY}", "X-Project": "web"}}}
	got = want(t, r.do(http.MethodPost, "/servers", adminKey, httpServer), http.StatusCreated)
	headers := got["auth"].(map[string]any)["headers"].(map[string]any)
	if headers["X-Project"].(map[string]any)["value"] != "web" || headers["Authorization"].(map[string]any)["ref"] != "Bearer ${LOGBOOK_KEY}" {
		t.Fatalf("headers %v", headers)
	}

	tests := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"literal env", map[string]any{"name": "a", "transport": "stdio", "command": "mcp-a", "env": map[string]string{"TOKEN": "hunter2"}}, "env.TOKEN"},
		{"literal beside a reference", map[string]any{"name": "a", "transport": "stdio", "command": "mcp-a", "env": map[string]string{"TOKEN": "hunter2${X}"}}, "env.TOKEN"},
		{"literal as a scheme", map[string]any{"name": "b", "transport": "streamable_http", "url": "http://b", "auth": map[string]any{"headers": map[string]string{"Authorization": "hunter2 ${X}"}}}, "auth.headers.Authorization"},
		{"climbing command", map[string]any{"name": "c", "transport": "stdio", "command": "mcp-x/../../bin/sh"}, "command"},
		{"dir with an allowlist", map[string]any{"name": "c", "transport": "stdio", "command": "mcp-x", "dir": "/tmp"}, "dir"},
		{"loader env", map[string]any{"name": "c", "transport": "stdio", "command": "mcp-x", "env": map[string]string{"LD_PRELOAD": "${EVIL}"}}, "env.LD_PRELOAD"},
		{"literal secret header", map[string]any{"name": "b", "transport": "streamable_http", "url": "http://b", "auth": map[string]any{"headers": map[string]string{"X-Api-Key": "hunter2"}}}, "auth.headers.X-Api-Key"},
		{"command not allowed", map[string]any{"name": "c", "transport": "stdio", "command": "rm"}, "command"},
		{"bad duration", map[string]any{"name": "d", "transport": "stdio", "command": "mcp-d", "call_timeout": "soon"}, "call_timeout"},
		{"bad name", map[string]any{"name": "Bad_Name", "transport": "stdio", "command": "mcp-e"}, "name"},
		{"no url", map[string]any{"name": "f", "transport": "streamable_http"}, "url"},
		{"relative url", map[string]any{"name": "f", "transport": "streamable_http", "url": "logbook:8420/mcp"}, "url"},
		{"password in the url", map[string]any{"name": "f", "transport": "streamable_http", "url": "https://bot:hunter2@b.example/mcp"}, "url"}, //nolint:gosec // a made-up password the API must refuse
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := r.do(http.MethodPost, "/servers", adminKey, tc.body)
			wantError(t, w, http.StatusBadRequest, "invalid", tc.field)
			if strings.Contains(w.Body.String(), "hunter2") {
				t.Fatal("the refusal repeats the secret")
			}
		})
	}

	patched := want(t, r.do(http.MethodPatch, "/servers/gh", adminKey, map[string]any{"args": []string{"stdio", "--read-only"}}), http.StatusOK)
	if len(patched["args"].([]any)) != 2 || patched["call_timeout"] != "30s" || patched["env"] == nil {
		t.Fatalf("patched %v", patched)
	}
	wantError(t, r.do(http.MethodPatch, "/servers/gh", adminKey, map[string]any{"env": map[string]any{"X": "plain"}}), http.StatusBadRequest, "invalid", "env.X")
	list := want(t, r.do(http.MethodGet, "/servers", viewerKey, nil), http.StatusOK)
	if len(items(t, list)) != 2 {
		t.Fatalf("list %v", list)
	}
}

func TestStderrOnlyForAdmins(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	h := &handler{d: Deps{Runtime: r.holder}}
	for _, tc := range []struct {
		id   *auth.Identity
		keep bool
	}{
		{identity("key:admin", "admin"), true},
		{identity("key:viewer", "viewer"), false},
	} {
		req := httptest.NewRequestWithContext(auth.WithIdentity(context.Background(), tc.id), http.MethodGet, "/", nil)
		status := map[string]any{"name": "gh", "stderr": []string{"token=hunter2"}}
		h.hideStderr(req, status)
		if _, kept := status["stderr"]; kept != tc.keep {
			t.Fatalf("%s: stderr kept %v, want %v", tc.id.Subject, kept, tc.keep)
		}
	}
}

func TestFileServerSecretsHidden(t *testing.T) {
	doc := baseDoc() + `
servers:
  - name: legacy
    transport: streamable_http
    url: http://bot:hunter2@legacy
    auth: {mode: static, headers: {Authorization: "Bearer hunter2"}}
    call_timeout: 15s
`
	r := newRig(t, doc, nil)
	w := r.do(http.MethodGet, "/servers/legacy", viewerKey, nil)
	got := want(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "hunter2") || got["call_timeout"] != "15s" {
		t.Fatalf("view %s", w.Body)
	}
}

func TestAPIKeys(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	created := want(t, r.do(http.MethodPost, "/api-keys", adminKey, map[string]any{"name": "ci", "groups": []string{"eng"}}), http.StatusCreated)
	plain, _ := created["key"].(string)
	if !strings.HasPrefix(plain, "alk_") {
		t.Fatalf("created %v", created)
	}
	w := r.do(http.MethodGet, "/api-keys/ci", viewerKey, nil)
	if strings.Contains(w.Body.String(), plain) || strings.Contains(w.Body.String(), "sha256") {
		t.Fatalf("the key or its hash came back: %s", w.Body)
	}
	want(t, r.do(http.MethodPost, "/role-bindings", adminKey, map[string]any{"name": "ci", "subjects": []string{"key:ci"}, "role": "member"}), http.StatusCreated)
	me := want(t, r.do(http.MethodGet, "/me", plain, nil), http.StatusOK)
	if me["subject"] != "key:ci" || me["role"] != "member" {
		t.Fatalf("me %v", me)
	}
	wantError(t, r.do(http.MethodPatch, "/api-keys/ci", adminKey, map[string]any{"sha256": "00"}), http.StatusBadRequest, "invalid", "sha256")
	patched := want(t, r.do(http.MethodPatch, "/api-keys/ci", adminKey, map[string]any{"expires_at": "2099-01-01T00:00:00Z"}), http.StatusOK)
	if patched["expires_at"] != "2099-01-01T00:00:00Z" {
		t.Fatalf("patched %v", patched)
	}
	want(t, r.do(http.MethodGet, "/me", plain, nil), http.StatusOK)
	revoked := want(t, r.do(http.MethodPost, "/api-keys/ci/revoke", adminKey, nil), http.StatusOK)
	if revoked["revoked"] != true {
		t.Fatalf("revoked %v", revoked)
	}
	if w := r.do(http.MethodGet, "/me", plain, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked key still works: %d", w.Code)
	}
	wantError(t, r.do(http.MethodPost, "/api-keys", adminKey, map[string]any{"name": "has space"}), http.StatusBadRequest, "invalid", "name")
	wantError(t, r.do(http.MethodPost, "/api-keys", adminKey, map[string]any{"name": "ci"}), http.StatusConflict, "already_exists", "name")
}

func TestSettings(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	w := r.do(http.MethodGet, "/settings", viewerKey, nil)
	got := want(t, w, http.StatusOK)
	if got["version"] != float64(0) || got["managed_by_file"] != false {
		t.Fatalf("settings %v", got)
	}
	got = want(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{
		"oidc": map[string]any{"issuer": "https://idp.example.com", "audience": "airlock"}, "public_url": "https://airlock.example.com",
	}, "If-Match", `"0"`), http.StatusOK)
	first, _ := got["version"].(float64)
	if first < 1 || got["oidc"].(map[string]any)["audience"] != "airlock" {
		t.Fatalf("patched %v", got)
	}
	if r.holder.Current().OIDC == nil {
		t.Fatal("OIDC is not live after the write")
	}
	got = want(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"oidc": map[string]any{"groups_claim": "roles"}}), http.StatusOK)
	if o := got["oidc"].(map[string]any); o["groups_claim"] != "roles" || o["issuer"] != "https://idp.example.com" {
		t.Fatalf("merge lost fields: %v", o)
	}
	if got["version"].(float64) <= first {
		t.Fatalf("version did not grow: %v after %v", got["version"], first)
	}
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"public_url": nil}, "If-Match", fmt.Sprintf(`"%d"`, int64(first))), http.StatusConflict, "version_conflict", "If-Match")
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"colour": "red"}), http.StatusBadRequest, "invalid", "colour")
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"default_profile": "gold"}), http.StatusBadRequest, "invalid", "default_profile")
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"oidc": map[string]any{"issuer": "idp"}}), http.StatusBadRequest, "invalid", "oidc.issuer")
	wantError(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"oidc": map[string]any{"extra": 1}}), http.StatusBadRequest, "invalid", "")
	got = want(t, r.do(http.MethodPatch, "/settings", adminKey, map[string]any{"oidc": nil}), http.StatusOK)
	if _, ok := got["oidc"]; ok || r.holder.Current().OIDC != nil {
		t.Fatalf("oidc not cleared: %v", got)
	}
}

func TestMeAndCheck(t *testing.T) {
	doc := baseDoc() + `
profiles:
  - {name: free, limits: {tools.calls: {rate: 30/m}}}
settings:
  default_profile: free
`
	r := newRig(t, doc, nil)
	me := want(t, r.do(http.MethodGet, "/me", memberKey, nil), http.StatusOK)
	if me["subject"] != "key:member" || me["role"] != "member" || me["profile"] != "free" || me["method"] != "apikey" {
		t.Fatalf("me %v", me)
	}
	tools := items(t, want(t, r.do(http.MethodGet, "/me/tools", memberKey, nil), http.StatusOK))
	if len(tools) != 1 || tools[0]["tool"] != "github__create_issue" || tools[0]["rule"] != "eng" {
		t.Fatalf("my tools %v", tools)
	}
	got := items(t, want(t, r.do(http.MethodPost, "/check", viewerKey, map[string]any{"user": "alice", "groups": []string{"eng"}}), http.StatusOK))
	allowed := map[string]bool{"files__read": false, "github__create_issue": true, "github__delete_repo": false}
	if len(got) != 3 {
		t.Fatalf("check %v", got)
	}
	for _, d := range got {
		if allowed[d["tool"].(string)] != d["allow"].(bool) {
			t.Errorf("check %v", d)
		}
		if d["tool"] == "github__delete_repo" && !strings.Contains(d["reason"].(string), "github__delete_*") {
			t.Errorf("deny reason %v", d)
		}
	}
	one := items(t, want(t, r.do(http.MethodPost, "/check", viewerKey, map[string]any{"key": "ci", "tools": []string{"github__create_issue"}}), http.StatusOK))
	if len(one) != 1 || one[0]["allow"] != false || one[0]["rule"] != "default-deny" {
		t.Fatalf("check for a key %v", one)
	}
	wantError(t, r.do(http.MethodPost, "/check", viewerKey, map[string]any{}), http.StatusBadRequest, "invalid", "user")
	wantError(t, r.do(http.MethodPost, "/check", viewerKey, map[string]any{"user": "a", "key": "b"}), http.StatusBadRequest, "invalid", "key")
}

func identity(subject, key string) *auth.Identity {
	return &auth.Identity{Subject: subject, KeyName: key, Method: "apikey"}
}

func TestMemberSeesOnlyOwnAudit(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	now := time.Now().UTC()
	var events []audit.Event
	for i, s := range []string{"key:member", "key:other", "key:member", "key:other"} {
		events = append(events, audit.Event{Time: now.Add(time.Duration(i) * time.Second), Kind: audit.KindTool, Subject: s, Server: "github", Tool: "create_issue", Outcome: audit.OutcomeOK})
	}
	if err := r.st.InsertAudit(context.Background(), store.DefaultOrg, events); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/audit", "/audit?subject=key:other", "/audit?kind=tool&subject=key:other&server=github"} {
		got := items(t, want(t, r.do(http.MethodGet, path, memberKey, nil), http.StatusOK))
		if len(got) != 2 {
			t.Fatalf("%s: member got %d records", path, len(got))
		}
		for _, e := range got {
			if e["subject"] != "key:member" {
				t.Fatalf("%s: member read %v", path, e)
			}
		}
	}
	if got := items(t, want(t, r.do(http.MethodGet, "/audit?subject=key:other", viewerKey, nil), http.StatusOK)); len(got) != 2 {
		t.Fatalf("viewer got %d", len(got))
	}
	page := want(t, r.do(http.MethodGet, "/audit?limit=3", viewerKey, nil), http.StatusOK)
	next := page["next_cursor"].(string)
	rest := items(t, want(t, r.do(http.MethodGet, "/audit?limit=3&cursor="+next, viewerKey, nil), http.StatusOK))
	if len(items(t, page)) != 3 || len(rest) != 1 {
		t.Fatalf("pages %d and %d", len(items(t, page)), len(rest))
	}
	wantError(t, r.do(http.MethodGet, "/audit?kind=weird", viewerKey, nil), http.StatusBadRequest, "invalid", "kind")
	wantError(t, r.do(http.MethodGet, "/audit?since=yesterday", viewerKey, nil), http.StatusBadRequest, "invalid", "since")
	wantError(t, r.do(http.MethodGet, "/audit?cursor="+cursor("x"), viewerKey, nil), http.StatusBadRequest, "invalid", "cursor")
}

func TestStatusToolsAndOpenAPI(t *testing.T) {
	r := newRig(t, baseDoc(), nil)
	st := want(t, r.do(http.MethodGet, "/status", viewerKey, nil), http.StatusOK)
	if st["version"] != "test" || st["storage"] != "sqlite" || st["instance"] != "test-1" || st["uptime_seconds"].(float64) < 59 {
		t.Fatalf("status %v", st)
	}
	tools := items(t, want(t, r.do(http.MethodGet, "/tools?server=github", viewerKey, nil), http.StatusOK))
	if len(tools) != 2 || tools[0]["tool"] != "create_issue" || tools[0]["description"] != "does github__create_issue" {
		t.Fatalf("tools %v", tools)
	}
	if got := r.do(http.MethodGet, "/me", viewerKey, nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
	w := r.do(http.MethodGet, "/openapi.yaml", viewerKey, nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Body.String(), "openapi: 3.1.0") {
		t.Fatalf("openapi %d", w.Code)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, Prefix+"/nope", nil)
	req.Header.Set("Authorization", "Bearer "+viewerKey)
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	wantError(t, rec, http.StatusNotFound, "not_found", "")
}
