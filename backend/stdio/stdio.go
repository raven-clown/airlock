// Package stdio runs an MCP server as a child process and talks to it over stdin and stdout.
package stdio

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/config"
)

const stderrLines = 100

// Options tune restarts.
type Options struct {
	BackoffBase time.Duration
	BackoffMax  time.Duration
}

// DefaultOptions restart after 1s, doubling up to 60s.
var DefaultOptions = Options{BackoffBase: time.Second, BackoffMax: 60 * time.Second}

// Backend is one stdio MCP server process, restarted when it exits.
type Backend struct {
	cfg  backend.Config
	deps backend.Deps
	opts Options
	log  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	status backend.Status
	cli    *client.Client
	stderr []string

	tools atomic.Pointer[[]mcp.Tool]

	cbMu      sync.Mutex
	callbacks []func()
}

// New returns a stdio backend. Call Start to launch it.
func New(cfg backend.Config, deps backend.Deps, opts Options) *Backend {
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	if deps.Env == nil {
		deps.Env = os.LookupEnv
	}
	b := &Backend{cfg: cfg, deps: deps, opts: opts, log: log.With("backend", cfg.Name), done: make(chan struct{})}
	b.status = backend.Status{State: backend.StateStarting, Since: time.Now()}
	empty := []mcp.Tool{}
	b.tools.Store(&empty)
	return b
}

func init() {
	backend.Register(backend.TransportStdio, func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
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
	s.Stderr = append([]string(nil), b.stderr...)
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
	return nil
}

// Call implements backend.Backend.
func (b *Backend) Call(ctx context.Context, _ *auth.Identity, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	b.mu.Lock()
	cli := b.cli
	b.mu.Unlock()
	if cli == nil {
		return nil, backend.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	res, err := cli.CallTool(ctx, req)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, err
}

func (b *Backend) setStatus(state string, err error) {
	b.mu.Lock()
	b.status.State = state
	b.status.Err = ""
	if err != nil {
		b.status.Err = err.Error()
	}
	b.status.Since = time.Now()
	b.mu.Unlock()
}

func (b *Backend) supervise() {
	defer close(b.done)
	delay := b.opts.BackoffBase
	for {
		connected, err := b.runOnce()
		if b.ctx.Err() != nil {
			b.setStatus(backend.StateDown, nil)
			return
		}
		b.setStatus(backend.StateDown, err)
		b.log.Warn("backend down", "error", err, "retry_in", delay.String())
		if connected {
			delay = b.opts.BackoffBase
		}
		select {
		case <-b.ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, b.opts.BackoffMax)
	}
}

// runOnce starts the process, serves until it exits, and reports whether it connected.
func (b *Backend) runOnce() (bool, error) {
	env := os.Environ()
	for k, v := range b.cfg.Env {
		val, err := config.Expand(v, b.deps.Env)
		if err != nil {
			return false, fmt.Errorf("env %s: %w", k, err)
		}
		env = append(env, k+"="+val)
	}

	cmd := exec.CommandContext(b.ctx, b.cfg.Command, b.cfg.Args...) //nolint:gosec // commands come from the operator's config
	cmd.Dir = b.cfg.Dir
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return false, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return false, err
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	if err := cmd.Start(); err != nil {
		_ = outR.Close()
		_ = outW.Close()
		_ = errR.Close()
		_ = errW.Close()
		return false, fmt.Errorf("starting %s: %w", b.cfg.Command, err)
	}
	_ = outW.Close()
	_ = errW.Close()

	stderrDone := make(chan struct{})
	go b.readStderr(errR, stderrDone)

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	cli := client.NewClient(transport.NewIO(outR, stdin, io.NopCloser(strings.NewReader(""))))
	connected := false
	err = b.connect(cli)
	if err == nil {
		connected = true
		b.mu.Lock()
		b.cli = cli
		b.mu.Unlock()
		b.setStatus(backend.StateUp, nil)
		b.log.Info("backend up", "tools", len(b.Tools()))
		err = <-exited
		if err == nil {
			err = fmt.Errorf("process exited")
		} else {
			err = fmt.Errorf("process exited: %w", err)
		}
	} else {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-exited
	}

	b.mu.Lock()
	b.cli = nil
	b.mu.Unlock()
	_ = cli.Close()
	_ = outR.Close()
	<-stderrDone
	return connected, err
}

func (b *Backend) connect(cli *client.Client) error {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	if err := cli.Start(ctx); err != nil {
		return fmt.Errorf("starting client: %w", err)
	}
	cli.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == mcp.MethodNotificationToolsListChanged {
			go b.refresh(cli)
		}
	})
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "airlock", Version: "dev"}
	if _, err := cli.Initialize(ctx, init); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	tools, err := backend.ListAllTools(ctx, cli)
	if err != nil {
		return err
	}
	b.setTools(tools)
	return nil
}

func (b *Backend) refresh(cli *client.Client) {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	tools, err := backend.ListAllTools(ctx, cli)
	if err != nil {
		b.log.Warn("refreshing tools failed", "error", err)
		return
	}
	b.setTools(tools)
}

func (b *Backend) setTools(tools []mcp.Tool) {
	b.tools.Store(&tools)
	b.cbMu.Lock()
	cbs := append([]func(){}, b.callbacks...)
	b.cbMu.Unlock()
	for _, fn := range cbs {
		fn()
	}
}

func (b *Backend) readStderr(r io.ReadCloser, done chan<- struct{}) {
	defer close(done)
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		b.log.Info("backend stderr", "line", line)
		b.mu.Lock()
		b.stderr = append(b.stderr, line)
		if len(b.stderr) > stderrLines {
			b.stderr = b.stderr[len(b.stderr)-stderrLines:]
		}
		b.mu.Unlock()
	}
}
