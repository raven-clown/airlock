package stdio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/testutil"
)

var serverPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "airlock-stdio-test")
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

var fastRetry = Options{BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond}

func deps(env map[string]string) backend.Deps {
	return backend.Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Env: func(k string) (string, bool) {
			v, ok := env[k]
			return v, ok
		},
	}
}

func start(t *testing.T, cfg backend.Config, env map[string]string) *Backend {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "test"
	}
	if cfg.Command == "" {
		cfg.Command = serverPath
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 10 * time.Second
	}
	b := New(cfg, deps(env), fastRetry)
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitUp(t *testing.T, b *Backend) {
	t.Helper()
	waitFor(t, "backend up", func() bool { return b.Status().Up() })
}

func callTool(ctx context.Context, b *Backend, name string, args map[string]any) (*mcp.CallToolResult, error) {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return b.Call(ctx, nil, req)
}

func text(r *mcp.CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	tc, _ := r.Content[0].(mcp.TextContent)
	return tc.Text
}

func toolNames(b *Backend) []string {
	var names []string
	for _, t := range b.Tools() {
		names = append(names, t.Name)
	}
	return names
}

func TestStdioListAndCall(t *testing.T) {
	b := start(t, backend.Config{}, nil)
	waitUp(t, b)
	if !slices.Contains(toolNames(b), "echo") {
		t.Fatalf("tools = %v", toolNames(b))
	}
	if b.Status().Tools != len(b.Tools()) {
		t.Errorf("status tools = %d", b.Status().Tools)
	}
	res, err := callTool(context.Background(), b, "echo", map[string]any{"text": "hi"})
	if err != nil || text(res) != "hi" {
		t.Fatalf("echo = %v, %v", res, err)
	}
}

func TestStdioToolError(t *testing.T) {
	b := start(t, backend.Config{}, nil)
	waitUp(t, b)
	res, err := callTool(context.Background(), b, "fail", nil)
	if err != nil || !res.IsError {
		t.Fatalf("fail = %+v, %v", res, err)
	}
}

func TestStdioCrashRestarts(t *testing.T) {
	b := start(t, backend.Config{}, nil)
	waitUp(t, b)
	if _, err := callTool(context.Background(), b, "crash", nil); err == nil {
		t.Fatal("crash returned no error")
	}
	waitFor(t, "backend back up", func() bool {
		res, err := callTool(context.Background(), b, "echo", map[string]any{"text": "again"})
		return err == nil && text(res) == "again"
	})
}

func TestStdioListChanged(t *testing.T) {
	b := start(t, backend.Config{}, nil)
	changed := make(chan struct{}, 10)
	b.OnToolsChanged(func() { changed <- struct{}{} })
	waitUp(t, b)
	if _, err := callTool(context.Background(), b, "add_tool", map[string]any{"name": "new"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new tool", func() bool { return slices.Contains(toolNames(b), "new") })
	select {
	case <-changed:
	default:
		t.Fatal("OnToolsChanged did not fire")
	}
}

func TestStdioCancel(t *testing.T) {
	b := start(t, backend.Config{}, nil)
	waitUp(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := callTool(ctx, b, "wait", nil)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled call did not return")
	}
}

func TestStdioTimeout(t *testing.T) {
	b := start(t, backend.Config{CallTimeout: 50 * time.Millisecond}, nil)
	waitUp(t, b)
	_, err := callTool(context.Background(), b, "wait", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}

func TestStdioMissingCommand(t *testing.T) {
	b := start(t, backend.Config{Command: "does-not-exist-airlock"}, nil)
	waitFor(t, "down with error", func() bool {
		s := b.Status()
		return s.State == backend.StateDown && strings.Contains(s.Err, "does-not-exist-airlock")
	})
	since := b.Status().Since
	waitFor(t, "a retry", func() bool { return b.Status().Since.After(since) })
	if _, err := callTool(context.Background(), b, "echo", nil); !errors.Is(err, backend.ErrUnavailable) {
		t.Fatalf("call error = %v, want ErrUnavailable", err)
	}
}

func TestStdioUnsetEnv(t *testing.T) {
	b := start(t, backend.Config{Env: map[string]string{"SETTING": "${AIRLOCK_TEST_UNSET}"}}, nil)
	waitFor(t, "down with env error", func() bool {
		s := b.Status()
		return s.State == backend.StateDown && strings.Contains(s.Err, "variable AIRLOCK_TEST_UNSET is not set")
	})
}

func TestStdioEnvResolved(t *testing.T) {
	b := start(t, backend.Config{Env: map[string]string{"AIRLOCK_X": "${Y}"}}, map[string]string{"Y": "z"})
	waitUp(t, b)
	res, err := callTool(context.Background(), b, "env", map[string]any{"name": "AIRLOCK_X"})
	if err != nil || text(res) != "z" {
		t.Fatalf("env = %v, %v", text(res), err)
	}
}

func TestStdioStderrKept(t *testing.T) {
	b := start(t, backend.Config{Args: []string{"--stderr"}}, nil)
	waitUp(t, b)
	waitFor(t, "stderr lines", func() bool {
		lines := b.Status().Stderr
		return len(lines) == 100 && lines[99] == "line 149"
	})
	if got := b.Status().Stderr[0]; got != "line 50" {
		t.Errorf("first kept line = %q", got)
	}
}

func TestRegistered(t *testing.T) {
	s := backend.NewSet(deps(nil))
	t.Cleanup(func() { _ = s.Close() })
	err := s.Apply(context.Background(), []backend.Config{{Name: "x", Transport: backend.TransportStdio, Command: serverPath, CallTimeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.Get("x")
	waitFor(t, "registered backend up", func() bool { return b.Status().Up() })
}
