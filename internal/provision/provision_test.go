package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

const doc = `
settings:
  allowed_origins: ["http://localhost:*"]
api_keys:
  - name: ci
    sha256: ` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `
servers:
  - name: github
    transport: stdio
    command: gh
    env:
      TOKEN: ${GH}
rules:
  - name: ci
    subjects: ["key:ci"]
    allow: ["github__*"]
role_bindings:
  - name: admins
    subjects: ["group:ops"]
    role: admin
`

func parse(t *testing.T, s string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(s), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRows(t *testing.T) {
	rows, err := Rows(parse(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[store.Kind][]string{
		store.KindServers:      {"github"},
		store.KindRules:        {"ci"},
		store.KindAPIKeys:      {"ci"},
		store.KindRoleBindings: {"admins"},
		store.KindSettings:     {"allowed_origins"},
	}
	for k, names := range want {
		if len(rows[k]) != len(names) {
			t.Errorf("%s = %v, want %v", k, rows[k], names)
		}
		for _, n := range names {
			if rows[k][n] == nil {
				t.Errorf("%s %q missing", k, n)
			}
		}
	}
	if !strings.Contains(string(rows[store.KindServers]["github"]), `"TOKEN":"${GH}"`) {
		t.Errorf("server spec = %s, want the ${GH} reference kept", rows[store.KindServers]["github"])
	}
	var origins []string
	if err := json.Unmarshal(rows[store.KindSettings]["allowed_origins"], &origins); err != nil || len(origins) != 1 {
		t.Errorf("allowed_origins = %s, %v", rows[store.KindSettings]["allowed_origins"], err)
	}
}

func TestRowsEmpty(t *testing.T) {
	rows, err := Rows(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range store.Kinds {
		if m, ok := rows[k]; !ok || len(m) != 0 {
			t.Errorf("%s = %v, want present and empty", k, m)
		}
	}
}

func TestApply(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	changed, err := Apply(ctx, st, store.DefaultOrg, parse(t, doc))
	if err != nil || !changed {
		t.Fatalf("Apply = %v, %v", changed, err)
	}
	if r, err := st.Get(ctx, store.DefaultOrg, store.KindServers, "github"); err != nil || r.Source != store.SourceFile {
		t.Errorf("github = %+v, %v", r, err)
	}
	if changed, err := Apply(ctx, st, store.DefaultOrg, parse(t, doc)); err != nil || changed {
		t.Errorf("second Apply = %v, %v", changed, err)
	}
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func startWatch(t *testing.T, path string, st *store.Store, logs *logBuffer) {
	t.Helper()
	cfg, err := config.Load(path, config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), st, store.DefaultOrg, cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	ready := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, path, config.Env{}, st, store.DefaultOrg, WatchOptions{
			Every: 10 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(logs, nil)), Ready: ready, Process: cfg,
		})
	}()
	<-ready
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWatchApplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	write(t, path, doc)
	st := openStore(t)
	startWatch(t, path, st, &logBuffer{})
	write(t, path, strings.Replace(doc, "name: github", "name: gitlab", 1))
	waitFor(t, "gitlab in the store", func() bool {
		_, err := st.Get(context.Background(), store.DefaultOrg, store.KindServers, "gitlab")
		return err == nil
	})
	if _, err := st.Get(context.Background(), store.DefaultOrg, store.KindServers, "github"); err == nil {
		t.Error("github still in the store")
	}
}

func TestWatchBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	write(t, path, doc)
	st := openStore(t)
	logs := &logBuffer{}
	startWatch(t, path, st, logs)
	before, _ := st.Revision(context.Background(), store.DefaultOrg)
	write(t, path, "servers: [\n")
	waitFor(t, "the reload error", func() bool { return strings.Contains(logs.String(), "config reload failed") })
	if after, _ := st.Revision(context.Background(), store.DefaultOrg); after != before {
		t.Errorf("revision moved from %d to %d", before, after)
	}
}

func TestWatchProcessWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	write(t, path, doc)
	st := openStore(t)
	logs := &logBuffer{}
	startWatch(t, path, st, logs)
	write(t, path, "listen_addr: 127.0.0.1:9\n"+doc)
	waitFor(t, "the restart warning", func() bool {
		s := logs.String()
		return strings.Contains(s, "restart airlock to apply") && strings.Contains(s, "listen_addr")
	})
}

func TestWatchNameTaken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	write(t, path, doc)
	st := openStore(t)
	logs := &logBuffer{}
	startWatch(t, path, st, logs)
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindRules, "api-rule", json.RawMessage(`{"name":"api-rule","subjects":["*"]}`)); err != nil {
		t.Fatal(err)
	}
	write(t, path, strings.Replace(doc, "role_bindings:", "  - name: api-rule\n    subjects: [\"*\"]\n    allow: [\"*\"]\nrole_bindings:", 1))
	waitFor(t, "the name clash error", func() bool { return strings.Contains(logs.String(), "was created through the admin API") })
}
