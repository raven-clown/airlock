package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func connect(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.NewInProcessClient(New("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Initialize(ctx, mcp.InitializeRequest{}); err != nil {
		t.Fatal(err)
	}
	return c
}

func call(ctx context.Context, t *testing.T, c *client.Client, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	res, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func text(r *mcp.CallToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	if tc, ok := r.Content[0].(mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestTools(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	res, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"echo", "fail", "crash", "wait", "add_tool", "env", "bad name", "a__b"} {
		if !names[want] {
			t.Errorf("tool %q missing", want)
		}
	}

	if got := text(call(ctx, t, c, "echo", map[string]any{"text": "hi"})); got != "hi" {
		t.Errorf("echo = %q", got)
	}
	if got := text(call(ctx, t, c, "a__b", nil)); got != "a__b" {
		t.Errorf("a__b = %q", got)
	}
	if r := call(ctx, t, c, "fail", nil); !r.IsError || text(r) != "failed on purpose" {
		t.Errorf("fail = %+v", r)
	}
	t.Setenv("AIRLOCK_TESTSERVER_X", "z")
	if got := text(call(ctx, t, c, "env", map[string]any{"name": "AIRLOCK_TESTSERVER_X"})); got != "z" {
		t.Errorf("env = %q", got)
	}
}

func TestAddTool(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	changed := make(chan struct{}, 1)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == mcp.MethodNotificationToolsListChanged {
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	})
	call(ctx, t, c, "add_tool", map[string]any{"name": "new"})
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no list_changed notification")
	}
	if got := text(call(ctx, t, c, "new", nil)); got != "new" {
		t.Errorf("new = %q", got)
	}
}

func TestWaitCanceled(t *testing.T) {
	c := connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		res *mcp.CallToolResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		req := mcp.CallToolRequest{}
		req.Params.Name = "wait"
		res, err := c.CallTool(ctx, req)
		done <- outcome{res, err}
	}()
	cancel()
	select {
	case o := <-done:
		// In process, a cancel can reach the handler first, which then returns its own result.
		if o.err == nil && text(o.res) != "canceled" {
			t.Fatalf("canceled call returned %+v", o.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return after cancel")
	}
}
