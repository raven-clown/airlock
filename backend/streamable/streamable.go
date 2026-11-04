// Package streamable connects to MCP servers over Streamable HTTP.
package streamable

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/httpx"
)

const (
	defaultMaxSessions = 256
	defaultIdleTimeout = 10 * time.Minute
)

// Options tune reconnects and health checks.
type Options struct {
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// CheckEvery is how often the tool list is fetched again. A failed fetch marks the backend down.
	CheckEvery time.Duration
	Now        func() time.Time
}

// DefaultOptions reconnect after 1s up to 60s and check every 30s.
var DefaultOptions = Options{BackoffBase: time.Second, BackoffMax: 60 * time.Second, CheckEvery: 30 * time.Second}

// Backend is one Streamable HTTP MCP server.
type Backend struct {
	cfg  backend.Config
	opts Options
	log  *slog.Logger
	pool *pool

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	broken chan struct{}

	mu      sync.Mutex
	status  backend.Status
	control *client.Client

	tools atomic.Pointer[[]mcp.Tool]

	cbMu      sync.Mutex
	callbacks []func()
}

// New returns a Streamable HTTP backend. Call Start to connect.
func New(cfg backend.Config, deps backend.Deps, opts Options) *Backend {
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	b := &Backend{cfg: cfg, opts: opts, log: log.With("backend", cfg.Name), done: make(chan struct{}), broken: make(chan struct{}, 1)}
	b.status = backend.Status{State: backend.StateStarting, Since: opts.Now()}
	empty := []mcp.Tool{}
	b.tools.Store(&empty)
	if cfg.Auth.Mode == backend.AuthForward {
		maxSessions, idle := cfg.Auth.MaxSessions, cfg.Auth.SessionIdleTimeout
		if maxSessions <= 0 {
			maxSessions = defaultMaxSessions
		}
		if idle <= 0 {
			idle = defaultIdleTimeout
		}
		b.pool = newPool(maxSessions, idle, opts.Now, b.dialCaller)
	}
	return b
}

func init() {
	backend.Register(backend.TransportStreamable, func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
		return New(cfg, deps, DefaultOptions), nil
	})
}

// Name implements backend.Backend.
func (b *Backend) Name() string { return b.cfg.Name }

// Tools implements backend.Backend.
func (b *Backend) Tools() []mcp.Tool { return *b.tools.Load() }

// OnToolsChanged implements backend.Backend.
func (b *Backend) OnToolsChanged(fn func()) {
	b.cbMu.Lock()
	defer b.cbMu.Unlock()
	b.callbacks = append(b.callbacks, fn)
}

// Status implements backend.Backend.
func (b *Backend) Status() backend.Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.status
	s.Tools = len(*b.tools.Load())
	return s
}

// Start implements backend.Backend. It returns at once and connects in the background.
func (b *Backend) Start(ctx context.Context) error {
	b.ctx, b.cancel = context.WithCancel(context.WithoutCancel(ctx))
	go b.supervise()
	return nil
}

// Close implements backend.Backend.
func (b *Backend) Close() error {
	if b.cancel == nil {
		return nil
	}
	b.cancel()
	<-b.done
	if b.pool != nil {
		b.pool.closeAll()
	}
	return nil
}

// Call implements backend.Backend.
func (b *Backend) Call(ctx context.Context, id *auth.Identity, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	b.mu.Lock()
	control := b.control
	b.mu.Unlock()
	if control == nil {
		return nil, backend.ErrUnavailable
	}
	cli := control
	if b.pool != nil {
		if id == nil || id.Token == "" {
			return nil, errors.New("forward mode needs the caller's token")
		}
		var err error
		if cli, err = b.pool.get(ctx, id.Subject, id.Token); err != nil {
			b.markBroken()
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	res, err := cli.CallTool(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if b.pool != nil {
			b.pool.drop(id.Subject, id.Token)
		}
		b.markBroken()
	}
	return res, err
}

func (b *Backend) markBroken() {
	select {
	case b.broken <- struct{}{}:
	default:
	}
}

func (b *Backend) setStatus(state string, err error) {
	b.mu.Lock()
	b.status.State = state
	b.status.Err = ""
	if err != nil {
		b.status.Err = err.Error()
	}
	b.status.Since = b.opts.Now()
	b.mu.Unlock()
}

func (b *Backend) supervise() {
	defer close(b.done)
	delay := b.opts.BackoffBase
	for {
		err := b.runOnce()
		if b.ctx.Err() != nil {
			b.setStatus(backend.StateDown, nil)
			return
		}
		b.setStatus(backend.StateDown, err)
		b.log.Warn("backend down", "error", err, "retry_in", delay.String())
		select {
		case <-b.ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, b.opts.BackoffMax)
	}
}

// runOnce connects the control session and holds it until a health check fails.
func (b *Backend) runOnce() error {
	headers := b.cfg.Auth.Headers
	if b.cfg.Auth.Mode == backend.AuthForward {
		headers = b.cfg.Auth.DiscoveryHeaders
	}
	cli, err := b.dial(b.ctx, headers)
	if err != nil {
		return err
	}
	cli.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == mcp.MethodNotificationToolsListChanged {
			go func() { _ = b.refresh(cli) }()
		}
	})
	if err := b.refresh(cli); err != nil {
		_ = cli.Close()
		return err
	}
	// Servers on the 2026-07-28 protocol only send list_changed on a listen stream.
	// Older servers fail here, and the periodic check picks up their changes.
	if stop, err := cli.ListenAsync(b.ctx, mcp.SubscriptionFilter{ToolsListChanged: true}, nil); err == nil {
		defer stop()
	}
	b.mu.Lock()
	b.control = cli
	b.mu.Unlock()
	b.setStatus(backend.StateUp, nil)
	b.log.Info("backend up", "tools", len(b.Tools()))

	defer func() {
		b.mu.Lock()
		b.control = nil
		b.mu.Unlock()
		_ = cli.Close()
	}()
	ticker := time.NewTicker(b.opts.CheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return nil
		case <-ticker.C:
		case <-b.broken:
		}
		if b.pool != nil {
			b.pool.sweep()
		}
		if err := b.refresh(cli); err != nil {
			return fmt.Errorf("health check: %w", err)
		}
	}
}

func (b *Backend) refresh(cli *client.Client) error {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	tools, err := backend.ListAllTools(ctx, cli)
	if err != nil {
		b.log.Warn("listing tools failed", "error", err)
		return err
	}
	if old := b.tools.Swap(&tools); reflect.DeepEqual(*old, tools) {
		return nil
	}
	b.cbMu.Lock()
	cbs := append([]func(){}, b.callbacks...)
	b.cbMu.Unlock()
	for _, fn := range cbs {
		fn()
	}
	return nil
}

func (b *Backend) dialCaller(ctx context.Context, token string) (*client.Client, error) {
	return b.dial(ctx, map[string]string{"Authorization": "Bearer " + token})
}

func (b *Backend) dial(ctx context.Context, headers map[string]string, extra ...transport.StreamableHTTPCOption) (*client.Client, error) {
	opts := append([]transport.StreamableHTTPCOption{
		transport.WithHTTPHeaders(headers),
		transport.WithHTTPLogger(b.log),
		transport.WithHTTPHeaderFunc(func(ctx context.Context) map[string]string {
			out := map[string]string{}
			for k, v := range httpx.HeadersFromContext(ctx) {
				out[k] = v[0]
			}
			return out
		}),
	}, extra...)
	tr, err := transport.NewStreamableHTTP(b.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating transport: %w", err)
	}
	cli := client.NewClient(tr)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := cli.Start(context.WithoutCancel(ctx)); err != nil {
		return nil, fmt.Errorf("starting client: %w", err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "airlock", Version: "dev"}
	if _, err := cli.Initialize(ctx, init); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return cli, nil
}
