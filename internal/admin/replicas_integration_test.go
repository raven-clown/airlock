//go:build integration

package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/httpx"
	"github.com/raven-clown/airlock/internal/provision"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/internal/store/storetest"
	"github.com/raven-clown/airlock/policy"
)

type replica struct {
	holder   *runtime.Holder
	reloader *runtime.Reloader
	src      *runtime.StoreSource
	st       *store.Store
}

// newReplica is one airlock instance on the shared database, as serve starts it.
func newReplica(t *testing.T, dsn, org string, cfg *config.Config) *replica {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := provision.Apply(ctx, st, org, cfg); err != nil {
		t.Fatal(err)
	}
	src := runtime.NewStoreSource(st, org, cfg)
	snap, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	holder := runtime.NewHolder(snap)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &replica{holder: holder, src: src, st: st, reloader: runtime.NewReloader(src, holder, runtime.WatchOptions{Every: 2 * time.Second, Logger: log})}
}

// TestReplicasShareChanges: a rule written through one replica's admin API is enforced by
// another within the 2 seconds the contract allows, plus the time a load takes.
func TestReplicasShareChanges(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AIRLOCK_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AIRLOCK_TEST_POSTGRES_DSN is not set")
	}
	cfg, err := config.Parse([]byte(baseDoc()), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	org := storetest.NewOrg(t)
	a := newReplica(t, dsn, org, cfg)
	b := newReplica(t, dsn, org, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Read the starting revision first, as a replica that is already running has.
	if _, err := b.reloader.Check(ctx); err != nil {
		t.Fatal(err)
	}
	go b.reloader.Run(ctx)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	adm := New(Deps{Store: a.st, Org: org, Source: a.src, Runtime: a.holder, Reloader: a.reloader, Catalog: catalog,
		Process: cfg, Logger: log, Version: "test", Started: time.Now()})
	h := httpx.Front(httpx.FrontOptions{Runtime: a.holder, Logger: log}, adm)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, Prefix+"/rules",
		strings.NewReader(`{"name":"files","subjects":["key:viewer"],"allow":["files__*"]}`))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	w := httptest.NewRecorder()
	written := time.Now()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create on replica a: %d %s", w.Code, w.Body)
	}
	viewer := identity("key:viewer", "viewer")
	for {
		d := b.holder.Current().Policy.Decide(ctx, policy.Request{Identity: viewer, Tool: "files__read"})
		if d.Allow {
			break
		}
		if time.Since(written) > 3*time.Second {
			t.Fatal("replica b did not enforce the new rule within 3 seconds")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("replica b enforced the rule %v after the write", time.Since(written).Round(time.Millisecond))
}
