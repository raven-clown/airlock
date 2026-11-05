package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/provision"
	"github.com/raven-clown/airlock/internal/store"
)

func storeWith(t *testing.T, doc string) (*store.Store, *config.Config) {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg, err := config.Parse([]byte(doc), config.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Apply(context.Background(), st, store.DefaultOrg, cfg); err != nil {
		t.Fatal(err)
	}
	return st, cfg
}

const storeDoc = `
listen_addr: 127.0.0.1:9
settings:
  allowed_origins: ["http://localhost:*"]
api_keys:
  - name: ci
    sha256: HASH
rules:
  - name: ci
    subjects: ["key:ci"]
    allow: ["demo__*"]
servers:
  - name: demo
    transport: stdio
    command: demo
role_bindings:
  - name: admins
    subjects: ["group:ops"]
    role: admin
`

func storeDocWithKey() string { return strings.Replace(storeDoc, "HASH", apikey.Hash(keyPlain), 1) }

func TestStoreSourceBuildsSnapshot(t *testing.T) {
	st, cfg := storeWith(t, storeDocWithKey())
	process := config.Default()
	process.ListenAddr = cfg.ListenAddr
	src := NewStoreSource(st, store.DefaultOrg, process)
	s, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !allows(s, "demo__echo") || allows(s, "other__x") {
		t.Error("policy or keys not built from the store")
	}
	if len(s.Servers) != 1 || s.Servers[0].Name != "demo" || s.ListenAddr != "127.0.0.1:9" {
		t.Errorf("snapshot = %+v", s)
	}
	if !reflect.DeepEqual(s.Settings.AllowedOrigins, []string{"http://localhost:*"}) {
		t.Errorf("settings = %+v", s.Settings)
	}
	if len(s.RoleBindings) != 1 || s.RoleBindings[0].Role != config.RoleAdmin {
		t.Errorf("role bindings = %+v", s.RoleBindings)
	}
	rev, _ := st.Revision(context.Background(), store.DefaultOrg)
	if s.Revision != rev {
		t.Errorf("snapshot revision = %d, store = %d", s.Revision, rev)
	}
	if v, err := src.Version(context.Background()); err != nil || v != "1" {
		t.Errorf("Version = %q, %v", v, err)
	}
}

func TestStoreSourceEmpty(t *testing.T) {
	st, _ := storeWith(t, "")
	s, err := NewStoreSource(st, store.DefaultOrg, config.Default()).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Servers) != 0 || len(s.Settings.AllowedOrigins) != 0 || s.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("snapshot = %+v", s)
	}
}

func watchStore(t *testing.T, src Source, logs *logBuffer) (*Holder, <-chan *Snapshot) {
	t.Helper()
	first, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHolder(first)
	swaps := make(chan *Snapshot, 10)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	go Watch(ctx, src, h, WatchOptions{Every: 10 * time.Millisecond, OnSwap: func(s *Snapshot) { swaps <- s }, Logger: slog.New(slog.NewTextHandler(logs, nil)), Ready: ready})
	<-ready
	return h, swaps
}

func TestWatchStoreSwaps(t *testing.T) {
	st, _ := storeWith(t, storeDocWithKey())
	h, swaps := watchStore(t, NewStoreSource(st, store.DefaultOrg, config.Default()), &logBuffer{})
	rule, _ := json.Marshal(map[string]any{"name": "more", "subjects": []string{"key:ci"}, "allow": []string{"other__*"}})
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindRules, "more", rule); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-swaps:
		if h.Current() != s || !allows(s, "other__x") {
			t.Error("swapped snapshot is wrong")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no swap after an API write")
	}
}

func TestStoreSourceBadRow(t *testing.T) {
	st, _ := storeWith(t, storeDocWithKey())
	logs := &logBuffer{}
	h, swaps := watchStore(t, NewStoreSource(st, store.DefaultOrg, config.Default()), logs)
	before := h.Current()
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindRules, "broken", json.RawMessage(`{"name":"broken","subjects":[]}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "config reload failed") {
		if time.Now().After(deadline) {
			t.Fatal("bad row not reported")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h.Current() != before {
		t.Error("snapshot replaced by a broken store")
	}
	if n := strings.Count(logs.String(), "config reload failed"); n != 1 {
		t.Errorf("error logged %d times, want once", n)
	}
	select {
	case <-swaps:
		t.Error("OnSwap called for a broken store")
	default:
	}
}

func TestStoreSourceBadJSON(t *testing.T) {
	st, _ := storeWith(t, "")
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindServers, "x", json.RawMessage(`{"name":`)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStoreSource(st, store.DefaultOrg, config.Default()).Load(context.Background()); err == nil || !strings.Contains(err.Error(), `servers "x"`) {
		t.Errorf("Load error = %v, want one naming servers \"x\"", err)
	}
}
