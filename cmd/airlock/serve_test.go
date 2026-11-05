package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/internal/testutil"
)

var serverPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "airlock-cli-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	serverPath, err = testutil.BuildTestServer(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const testKey = apikey.Prefix + "cli-test"

func writeTestConfig(t *testing.T) string {
	t.Helper()
	return writeConfigAllowing(t, "demo__*")
}

// dsnFor returns the database a test config written by writeConfigAllowing uses.
func dsnFor(path string) string {
	return "file:" + filepath.ToSlash(filepath.Join(filepath.Dir(path), "airlock.db"))
}

func openTestStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", dsnFor(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func writeConfigAllowing(t *testing.T, allow string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	doc := fmt.Sprintf(`
listen_addr: 127.0.0.1:0
storage:
  dsn: '%s'
stdio:
  identity: local
  groups: [eng]
api_keys:
  - name: ci
    sha256: %s
    groups: [eng]
servers:
  - name: demo
    transport: stdio
    command: '%s'
    required: true
rules:
  - name: eng
    subjects: ["group:eng"]
    allow: ["%s"]
`, dsnFor(path), apikey.Hash(testKey), serverPath, allow)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func listeningAddr(t *testing.T, logs *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(logs.String(), "\n") {
			var rec struct {
				Msg  string `json:"msg"`
				Addr string `json:"addr"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "listening" {
				return rec.Addr
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no listening line in %s", logs.String())
	return ""
}

func names(t *testing.T, c *client.Client) []string {
	t.Helper()
	res, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tool := range res.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeHTTP(t *testing.T) {
	path := writeTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), stdout, stderr, config.Env{})
	}()
	addr := listeningAddr(t, stdout)

	tr, err := transport.NewStreamableHTTP("http://"+addr+"/mcp", transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + testKey}))
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(tr)
	defer func() { _ = c.Close() }()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "demo__echo listed", func() bool { return slices.Contains(names(t, c), "demo__echo") })
	req := mcp.CallToolRequest{}
	req.Params.Name = "demo__echo"
	req.Params.Arguments = map[string]any{"text": "through airlock"}
	res, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if tc, _ := res.Content[0].(mcp.TextContent); tc.Text != "through airlock" {
		t.Errorf("echo = %+v", res)
	}
	waitFor(t, "audit line on stdout", func() bool { return strings.Contains(stdout.String(), `"log":"audit"`) })
	st := openTestStore(t, path)
	waitFor(t, "audit row in the store", func() bool {
		events, err := st.ListAudit(ctx, store.DefaultOrg, 0)
		return err == nil && len(events) > 0 && events[0].Tool == "echo" && events[0].Outcome == "ok"
	})

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, stderr = %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestServeStdio(t *testing.T) {
	path := writeTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cIn, sOut := io.Pipe()
	sIn, cOut := io.Pipe()
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", path, "--stdio"}, sIn, sOut, stderr, config.Env{})
		_ = sOut.Close()
	}()

	var seen syncBuffer
	c := client.NewClient(transport.NewIO(io.TeeReader(cIn, &seen), cOut, io.NopCloser(strings.NewReader(""))))
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "demo__echo over stdio", func() bool { return slices.Contains(names(t, c), "demo__echo") })

	sc := bufio.NewScanner(strings.NewReader(seen.String()))
	for sc.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil || msg["jsonrpc"] != "2.0" {
			t.Fatalf("non-protocol line on stdout: %q", sc.Text())
		}
	}
	if !strings.Contains(stderr.String(), `"msg"`) {
		t.Error("no logs on stderr in stdio mode")
	}

	_ = c.Close()
	_ = cOut.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("serve --stdio did not stop")
	}
}

func TestServeBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("servers:\n  - {name: Bad, transport: stdio, command: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"serve", "--config", path}, strings.NewReader(""), &stdout, &stderr, config.Env{})
	if code != 1 || !strings.Contains(stderr.String(), `invalid server name "Bad"`) {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestServeBadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--nope"}, strings.NewReader(""), &stdout, &stderr, config.Env{}); code != 2 {
		t.Errorf("code = %d", code)
	}
}

func TestServePortInUse(t *testing.T) {
	path := writeTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &syncBuffer{}
	go run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), first, &syncBuffer{}, config.Env{})
	addr := listeningAddr(t, first)
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), &stdout, &stderr, config.Env{"AIRLOCK_LISTEN_ADDR": addr})
	if code != 1 || !strings.Contains(stderr.String(), "listen") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func connect(ctx context.Context, t *testing.T, addr string) *client.Client {
	t.Helper()
	tr, err := transport.NewStreamableHTTP("http://"+addr+"/mcp", transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + testKey}))
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(tr)
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServeReloadsFromStore(t *testing.T) {
	path := writeConfigAllowing(t, "demo__echo")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), stdout, &syncBuffer{}, config.Env{})
	}()
	c := connect(ctx, t, listeningAddr(t, stdout))
	waitFor(t, "demo__echo listed", func() bool { return slices.Contains(names(t, c), "demo__echo") })
	if slices.Contains(names(t, c), "demo__fail") {
		t.Fatal("demo__fail listed before the API rule")
	}
	st := openTestStore(t, path)
	rule := json.RawMessage(`{"name":"api-all","subjects":["group:eng"],"allow":["demo__*"]}`)
	if _, err := st.Create(ctx, store.DefaultOrg, store.KindRules, "api-all", rule); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "demo__fail listed after the API rule", func() bool { return slices.Contains(names(t, c), "demo__fail") })
	cancel()
	<-done
}

func TestServeNameTaken(t *testing.T) {
	path := writeTestConfig(t)
	st := openTestStore(t, path)
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindServers, "demo", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"serve", "--config", path}, strings.NewReader(""), &stdout, &stderr, config.Env{})
	if code != 1 || !strings.Contains(stderr.String(), "was created through the admin API") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestMigrate(t *testing.T) {
	path := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"migrate", "--config", path}, strings.NewReader(""), &stdout, &stderr, config.Env{})
	if code != 0 || stdout.String() != fmt.Sprintf("schema version %d\n", store.LatestSchema) {
		t.Errorf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("storage:\n  driver: mysql\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run(context.Background(), []string{"migrate", "--config", bad}, strings.NewReader(""), &stdout, &stderr, config.Env{}); code != 1 || !strings.Contains(stderr.String(), "storage.driver") {
		t.Errorf("bad config: code %d, stderr %q", code, stderr.String())
	}
}
