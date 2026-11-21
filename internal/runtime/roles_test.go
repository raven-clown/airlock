package runtime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

func TestRole(t *testing.T) {
	s := &Snapshot{RoleBindings: []config.RoleBinding{
		{Name: "everyone", Subjects: []string{"*"}, Role: config.RoleMember},
		{Name: "auditors", Subjects: []string{"group:audit"}, Role: config.RoleViewer},
		{Name: "ops", Subjects: []string{"group:ops", "user:root"}, Role: config.RoleAdmin},
		{Name: "bot", Subjects: []string{"key:bootstrap"}, Role: config.RoleAdmin},
	}}
	tests := []struct {
		name string
		id   *auth.Identity
		want string
	}{
		{"anyone is a member", &auth.Identity{Subject: "bob"}, config.RoleMember},
		{"group viewer", &auth.Identity{Subject: "carol", Groups: []string{"audit"}}, config.RoleViewer},
		{"highest wins", &auth.Identity{Subject: "dave", Groups: []string{"audit", "ops"}}, config.RoleAdmin},
		{"user", &auth.Identity{Subject: "root"}, config.RoleAdmin},
		{"key", &auth.Identity{Subject: "key:bootstrap", KeyName: "bootstrap"}, config.RoleAdmin},
		{"a user named like a key is not the key", &auth.Identity{Subject: "bootstrap"}, config.RoleMember},
		{"no identity", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Role(tc.id); got != tc.want {
				t.Fatalf("role %q, want %q", got, tc.want)
			}
		})
	}
	if (&Snapshot{}).Role(&auth.Identity{Subject: "a"}) != "" {
		t.Fatal("no bindings gave a role")
	}
}

func TestHasRole(t *testing.T) {
	tests := []struct {
		role, need string
		want       bool
	}{
		{config.RoleAdmin, config.RoleViewer, true},
		{config.RoleViewer, config.RoleViewer, true},
		{config.RoleMember, config.RoleViewer, false},
		{"", config.RoleMember, false},
		{config.RoleAdmin, "", false},
	}
	for _, tc := range tests {
		if got := HasRole(tc.role, tc.need); got != tc.want {
			t.Errorf("HasRole(%q, %q) = %v", tc.role, tc.need, got)
		}
	}
}

func TestCaller(t *testing.T) {
	c := Caller(&auth.Identity{Subject: "key:ci", KeyName: "ci", Groups: []string{"g"}, Profile: "pro"})
	if c.Subject != "key:ci" || c.Key != "ci" || c.ClaimProfile != "pro" || len(c.Groups) != 1 {
		t.Fatalf("%+v", c)
	}
	if Caller(nil).Subject != "" {
		t.Fatal("nil identity")
	}
}

const oidcDoc = `
settings:
  oidc: {issuer: "https://idp.example.com", audience: airlock}
profiles:
  - name: free
    limits:
      requests: {rate: 1/h}
role_bindings:
  - {name: ops, subjects: ["group:ops"], role: admin}
`

func TestReloadKeepsOIDCAndCounters(t *testing.T) {
	ctx := context.Background()
	st, _ := storeWith(t, oidcDoc)
	src := NewStoreSource(st, store.DefaultOrg, config.Default())
	first, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.OIDC == nil || first.OIDC.Issuer() != "https://idp.example.com" {
		t.Fatal("no OIDC authenticator")
	}
	alice := Caller(&auth.Identity{Subject: "alice"})
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindSettings, "default_profile", json.RawMessage(`"free"`)); err != nil {
		t.Fatal(err)
	}
	second, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.OIDC != first.OIDC {
		t.Fatal("a reload that left OIDC alone made a new authenticator")
	}
	if _, d := second.Limits.Request(ctx, alice); d != nil {
		t.Fatal(d)
	}
	rule, _ := json.Marshal(map[string]any{"name": "r", "subjects": []string{"*"}, "allow": []string{"*"}})
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindRules, "r", rule); err != nil {
		t.Fatal(err)
	}
	third, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, d := third.Limits.Request(ctx, alice); d == nil {
		t.Fatal("a reload reset the counters")
	}

	row, err := st.Get(ctx, store.DefaultOrg, store.KindSettings, "oidc")
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != store.SourceFile {
		t.Fatal("oidc settings row is not from the file")
	}
}

func TestOIDCReplacedWhenSettingsChange(t *testing.T) {
	ctx := context.Background()
	st, _ := storeWith(t, "")
	src := NewStoreSource(st, store.DefaultOrg, config.Default())
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindSettings, "oidc", json.RawMessage(`{"issuer":"https://a.example","audience":"x"}`)); err != nil {
		t.Fatal(err)
	}
	first, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, store.DefaultOrg, store.KindSettings, "oidc", 1, json.RawMessage(`{"issuer":"https://b.example","audience":"x"}`)); err != nil {
		t.Fatal(err)
	}
	second, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.OIDC == first.OIDC || second.OIDC.Issuer() != "https://b.example" {
		t.Fatal("the issuer changed but the authenticator did not")
	}
}

func TestChangeBeforeFirstCheckIsLoaded(t *testing.T) {
	ctx := context.Background()
	st, _ := storeWith(t, "")
	src := NewStoreSource(st, store.DefaultOrg, config.Default())
	first, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHolder(first)
	r := NewReloader(src, h, WatchOptions{Start: StartVersion(first)})
	rule, _ := json.Marshal(map[string]any{"name": "late", "subjects": []string{"*"}, "allow": []string{"*"}})
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindRules, "late", rule); err != nil {
		t.Fatal(err)
	}
	if swapped, err := r.Check(ctx); !swapped || err != nil {
		t.Fatalf("a write made before the first check was not loaded: %v, %v", swapped, err)
	}
}

func TestBadProfileRowKeepsSnapshot(t *testing.T) {
	ctx := context.Background()
	st, _ := storeWith(t, "")
	src := NewStoreSource(st, store.DefaultOrg, config.Default())
	first, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHolder(first)
	r := NewReloader(src, h, WatchOptions{})
	if _, err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	var results []bool
	r.opts.OnResult = func(ok bool) { results = append(results, ok) }
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindProfiles, "bad", json.RawMessage(`{"name":"bad","limits":{"requests":{"rate":"fast"}}}`)); err != nil {
		t.Fatal(err)
	}
	swapped, err := r.Check(ctx)
	if swapped || err == nil || !strings.Contains(err.Error(), `rate "fast"`) {
		t.Fatalf("Check = %v, %v", swapped, err)
	}
	if h.Current() != first {
		t.Fatal("a bad profile replaced the snapshot")
	}
	if st := h.State(); st.Error == "" || st.At.IsZero() {
		t.Fatalf("state %+v", st)
	}
	if err := st.Delete(ctx, store.DefaultOrg, store.KindProfiles, "bad", 1); err != nil {
		t.Fatal(err)
	}
	if swapped, err := r.Check(ctx); !swapped || err != nil {
		t.Fatalf("fixed store: %v, %v", swapped, err)
	}
	if h.State().Error != "" {
		t.Fatal("error kept after a good reload")
	}
	if len(results) != 2 || results[0] || !results[1] {
		t.Fatalf("results %v", results)
	}
	if swapped, _ := r.Check(ctx); swapped {
		t.Fatal("swapped with no change")
	}
}
