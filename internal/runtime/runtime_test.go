package runtime

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/policy"
)

const keyPlain = apikey.Prefix + "runtime-test"

func writeConfig(t *testing.T, path, allow string) {
	t.Helper()
	doc := `
api_keys:
  - name: ci
    sha256: ` + apikey.Hash(keyPlain) + `
rules:
  - name: ci
    subjects: ["key:ci"]
    allow: ["` + allow + `"]
servers:
  - name: demo
    transport: stdio
    command: demo
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func allows(s *Snapshot, tool string) bool {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+keyPlain)
	id, err := s.Authenticator.Authenticate(context.Background(), r)
	if err != nil {
		return false
	}
	return s.Policy.Decide(context.Background(), policy.Request{Identity: id, Tool: tool}).Allow
}

func TestFileSourceBuildsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	writeConfig(t, path, "demo__*")
	s, err := NewFileSource(path, config.Env{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !allows(s, "demo__echo") || allows(s, "other__x") {
		t.Error("policy or keys not built from the file")
	}
	if len(s.Servers) != 1 || s.Servers[0].Name != "demo" || s.ListenAddr != "127.0.0.1:8080" || s.Stdio.Identity != "local" {
		t.Errorf("snapshot = %+v", s)
	}
}

func TestDefaultSource(t *testing.T) {
	src := NewFileSource("", config.Env{})
	s, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.ListenAddr != "127.0.0.1:8080" || len(s.Servers) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	if v, err := src.Version(context.Background()); err != nil || v != "default" {
		t.Errorf("Version = %q, %v", v, err)
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

func startWatch(t *testing.T, path string, logs *logBuffer) (*Holder, <-chan *Snapshot) {
	t.Helper()
	src := NewFileSource(path, config.Env{})
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

func TestWatchSwaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	writeConfig(t, path, "demo__*")
	h, swaps := startWatch(t, path, &logBuffer{})
	writeConfig(t, path, "other__*")
	select {
	case s := <-swaps:
		if h.Current() != s || !allows(s, "other__x") || allows(s, "demo__echo") {
			t.Error("swapped snapshot is wrong")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no swap after the file changed")
	}
}

func TestWatchKeepsOldOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	writeConfig(t, path, "demo__*")
	logs := &logBuffer{}
	h, swaps := startWatch(t, path, logs)
	before := h.Current()
	if err := os.WriteFile(path, []byte("listen_adr: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "config reload failed") {
		if time.Now().After(deadline) {
			t.Fatal("reload error not logged")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h.Current() != before {
		t.Error("snapshot replaced by a broken file")
	}
	select {
	case <-swaps:
		t.Error("OnSwap called for a broken file")
	default:
	}
	if n := strings.Count(logs.String(), "config reload failed"); n != 1 {
		t.Errorf("error logged %d times, want once", n)
	}
}

func TestHolderConcurrent(t *testing.T) {
	a, b := &Snapshot{ListenAddr: "a"}, &Snapshot{ListenAddr: "b"}
	h := NewHolder(a)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if s := h.Current(); s != a && s != b {
						t.Error("saw a torn snapshot")
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			h.Swap(b)
		} else {
			h.Swap(a)
		}
	}
	close(stop)
	wg.Wait()
}
