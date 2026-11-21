package admin

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/provision"
	"github.com/raven-clown/airlock/internal/store"
)

func emptyStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "b.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestBootstrap(t *testing.T) {
	ctx := context.Background()
	st := emptyStore(t)
	key, err := Bootstrap(ctx, st, store.DefaultOrg, false)
	if err != nil || !strings.HasPrefix(key, "alk_") {
		t.Fatalf("first start: %q, %v", key, err)
	}
	for _, name := range []string{BootstrapBinding, EveryoneBinding} {
		if _, err := st.Get(ctx, store.DefaultOrg, store.KindRoleBindings, name); err != nil {
			t.Fatalf("binding %s: %v", name, err)
		}
	}
	again, err := Bootstrap(ctx, st, store.DefaultOrg, false)
	if err != nil || again != "" {
		t.Fatalf("second start printed a key: %q, %v", again, err)
	}
	fresh, err := Bootstrap(ctx, st, store.DefaultOrg, true)
	if err != nil || fresh == "" || fresh == key {
		t.Fatalf("forced: %q, %v", fresh, err)
	}
	rows, _ := st.List(ctx, store.DefaultOrg, store.KindAPIKeys, "", 0)
	if len(rows) != 1 || rows[0].Version != 2 {
		t.Fatalf("keys %+v", rows)
	}
	events, _ := st.ListAudit(ctx, store.DefaultOrg, store.AuditQuery{})
	if len(events) != 4 {
		t.Fatalf("%d audit records, want 4", len(events))
	}
}

func TestBootstrapKeyWorks(t *testing.T) {
	r := newRig(t, "", nil)
	key, err := Bootstrap(context.Background(), r.st, store.DefaultOrg, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.reloader.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	me := want(t, r.do(http.MethodGet, "/me", key, nil), http.StatusOK)
	if me["role"] != "admin" || me["subject"] != "key:bootstrap" {
		t.Fatalf("me %v", me)
	}
	anyone := want(t, r.do(http.MethodPost, "/api-keys", key, map[string]any{"name": "someone"}), http.StatusCreated)
	if me := want(t, r.do(http.MethodGet, "/me", anyone["key"].(string), nil), http.StatusOK); me["role"] != "member" {
		t.Fatalf("a new key is not a member: %v", me)
	}
}

func TestBootstrapSkippedWithFileBindings(t *testing.T) {
	ctx := context.Background()
	st := emptyStore(t)
	cfg, err := config.Parse([]byte(baseDoc()), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Apply(ctx, st, store.DefaultOrg, cfg); err != nil {
		t.Fatal(err)
	}
	if key, err := Bootstrap(ctx, st, store.DefaultOrg, false); err != nil || key != "" {
		t.Fatalf("file bindings: %q, %v", key, err)
	}
}

func TestBootstrapRefusesFileKey(t *testing.T) {
	ctx := context.Background()
	st := emptyStore(t)
	cfg, err := config.Parse([]byte("api_keys:\n  - {name: bootstrap, sha256: "+strings.Repeat("a", 64)+"}\n"), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Apply(ctx, st, store.DefaultOrg, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(ctx, st, store.DefaultOrg, false); err == nil || !strings.Contains(err.Error(), "config file") {
		t.Fatalf("err = %v", err)
	}
}
