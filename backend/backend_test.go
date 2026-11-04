package backend

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth"
)

type fakeBackend struct {
	cfg     Config
	mu      sync.Mutex
	started bool
	closed  bool
	onTools []func()
}

func (f *fakeBackend) Name() string { return f.cfg.Name }
func (f *fakeBackend) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
	return nil
}
func (f *fakeBackend) Tools() []mcp.Tool { return []mcp.Tool{mcp.NewTool("t")} }
func (f *fakeBackend) Call(context.Context, *auth.Identity, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText("ok"), nil
}
func (f *fakeBackend) Status() Status { return Status{State: StateUp} }
func (f *fakeBackend) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}
func (f *fakeBackend) OnToolsChanged(fn func()) { f.onTools = append(f.onTools, fn) }

var (
	createdMu sync.Mutex
	created   []*fakeBackend
)

func init() {
	Register("fake", func(cfg Config, _ Deps) (Backend, error) {
		b := &fakeBackend{cfg: cfg}
		createdMu.Lock()
		created = append(created, b)
		createdMu.Unlock()
		return b, nil
	})
}

func TestSetApply(t *testing.T) {
	s := NewSet(Deps{})
	changes := 0
	s.OnChange(func() { changes++ })
	ctx := context.Background()

	a := Config{Name: "a", Transport: "fake"}
	b := Config{Name: "b", Transport: "fake"}
	if err := s.Apply(ctx, []Config{a, b}); err != nil {
		t.Fatal(err)
	}
	if len(s.All()) != 2 {
		t.Fatalf("All = %d backends", len(s.All()))
	}
	first, _ := s.Get("a")
	if !first.(*fakeBackend).started {
		t.Error("a was not started")
	}

	if err := s.Apply(ctx, []Config{a}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("b"); ok {
		t.Error("b still present")
	}

	a2 := a
	a2.Command = "changed"
	if err := s.Apply(ctx, []Config{a2}); err != nil {
		t.Fatal(err)
	}
	second, _ := s.Get("a")
	if second == first || !first.(*fakeBackend).closed {
		t.Error("changed a was not restarted")
	}

	if err := s.Apply(ctx, []Config{a2}); err != nil {
		t.Fatal(err)
	}
	same, _ := s.Get("a")
	if same != second {
		t.Error("unchanged a was restarted")
	}
	if changes != 3 {
		t.Errorf("OnChange fired %d times, want 3", changes)
	}

	second.(*fakeBackend).onTools[0]()
	if changes != 4 {
		t.Errorf("tool change did not fire OnChange")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !second.(*fakeBackend).closed || len(s.All()) != 0 {
		t.Error("Close left backends running")
	}
}

func TestSetUnknownTransport(t *testing.T) {
	s := NewSet(Deps{})
	err := s.Apply(context.Background(), []Config{{Name: "x", Transport: "pigeon"}})
	if err == nil || err.Error() != `backend "x": unknown transport "pigeon"` {
		t.Fatalf("error = %v", err)
	}
}

type pager struct{ pages [][]string }

func (p *pager) ListTools(_ context.Context, req mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	i := 0
	if req.Params.Cursor != "" {
		i = int(req.Params.Cursor[0] - '0')
	}
	if i >= len(p.pages) {
		return nil, errors.New("bad cursor")
	}
	res := &mcp.ListToolsResult{}
	for _, n := range p.pages[i] {
		res.Tools = append(res.Tools, mcp.NewTool(n))
	}
	if i+1 < len(p.pages) {
		res.NextCursor = mcp.Cursor(rune('0' + i + 1))
	}
	return res, nil
}

func TestListAllTools(t *testing.T) {
	tools, err := ListAllTools(context.Background(), &pager{pages: [][]string{{"a", "b"}, {"c"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 3 || tools[2].Name != "c" {
		t.Errorf("tools = %v", tools)
	}
}

func TestStatusUp(t *testing.T) {
	if (Status{State: StateUp}).Up() != true || (Status{State: StateDown}).Up() {
		t.Error("Up is wrong")
	}
}
