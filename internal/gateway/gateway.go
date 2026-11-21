// Package gateway serves one MCP endpoint that fronts every backend, filtered per caller.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/httpx"
	"github.com/raven-clown/airlock/internal/naming"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/policy"
	"github.com/raven-clown/airlock/telemetry"
)

// Options are a gateway's dependencies.
type Options struct {
	Backends *backend.Set
	Runtime  *runtime.Holder
	Audit    *audit.Pipeline
	Logger   *slog.Logger
	Instance string
	Version  string
	Metrics  *telemetry.Metrics
	// Tracer starts a span for a tool call that arrives with none, as over stdio.
	Tracer *telemetry.Tracer
}

// Gateway is the MCP server clients talk to.
type Gateway struct {
	opts       Options
	log        *slog.Logger
	mcp        *server.MCPServer
	streamable *server.StreamableHTTPServer
	sessions   *sessions
	refreshMu  sync.Mutex
	known      atomic.Pointer[map[string]bool]
}

// New builds a gateway and fills its catalog from the backends.
func New(opts Options) *Gateway {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	g := &Gateway{opts: opts, log: log, sessions: newSessions()}

	hooks := &server.Hooks{}
	hooks.AddOnUnregisterSession(func(_ context.Context, s server.ClientSession) {
		g.sessions.unbind(s.SessionID())
	})
	hooks.AddBeforeCallTool(g.auditDenied)

	g.mcp = server.NewMCPServer("airlock", opts.Version,
		server.WithToolCapabilities(true),
		server.WithToolFilter(g.filter),
		server.WithHooks(hooks),
		server.WithRecovery(),
	)
	g.streamable = server.NewStreamableHTTPServer(g.mcp,
		server.WithStateful(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			if id, ok := auth.FromContext(r.Context()); ok {
				ctx = auth.WithIdentity(ctx, id)
			}
			if span := telemetry.SpanFrom(r.Context()); span != nil {
				ctx = telemetry.WithSpan(ctx, span)
			}
			return httpx.WithForwardHeaders(ctx, r.Header)
		}),
	)
	opts.Backends.OnChange(g.Refresh)
	g.Refresh()
	return g
}

// MCPServer returns the underlying mcp-go server.
func (g *Gateway) MCPServer() *server.MCPServer { return g.mcp }

// HTTPHandler is the Streamable HTTP endpoint with session binding in front. It expects
// httpx.Front around it to sign the caller in.
func (g *Gateway) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "a valid API key or token is required")
			return
		}
		sid := r.Header.Get("Mcp-Session-Id")
		if sid == "" {
			g.streamable.ServeHTTP(&mintWriter{ResponseWriter: w, sessions: g.sessions, subject: id.Subject}, r)
			return
		}
		if !g.sessions.allow(sid, id.Subject) {
			g.log.Warn("unknown session or another caller's session", "subject", id.Subject, "request_id", r.Header.Get("X-Request-Id"))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		g.streamable.ServeHTTP(w, r)
		if r.Method == http.MethodDelete {
			g.sessions.unbind(sid)
		}
	})
}

// ServeStdio serves one client over in and out as id, until ctx ends or in closes.
func (g *Gateway) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, id *auth.Identity) error {
	s := server.NewStdioServer(g.mcp)
	s.SetContextFunc(func(ctx context.Context) context.Context { return auth.WithIdentity(ctx, id) })
	s.SetErrorLogger(slog.NewLogLogger(g.log.Handler(), slog.LevelError))
	return s.Listen(ctx, in, out)
}

func (g *Gateway) decide(ctx context.Context, id *auth.Identity, serverName, tool string, args map[string]any) policy.Decision {
	if id == nil {
		return policy.Decision{Rule: "no-identity", Reason: "no caller identity"}
	}
	return g.opts.Runtime.Current().Policy.Decide(ctx, policy.Request{Identity: id, Server: serverName, Tool: tool, Args: args})
}

func (g *Gateway) filter(ctx context.Context, tools []mcp.Tool) []mcp.Tool {
	id, _ := auth.FromContext(ctx)
	out := make([]mcp.Tool, 0, len(tools))
	for _, t := range tools {
		srv, _, _ := naming.Split(t.Name)
		if g.decide(ctx, id, srv, t.Name, nil).Allow {
			out = append(out, t)
		}
	}
	return out
}

// auditDenied records calls the tool filter is about to reject, since they never reach a handler.
func (g *Gateway) auditDenied(ctx context.Context, _ any, req *mcp.CallToolRequest) {
	id, _ := auth.FromContext(ctx)
	srv, tool, ok := naming.Split(req.Params.Name)
	if !ok {
		tool = req.Params.Name
	}
	d := g.decide(ctx, id, srv, req.Params.Name, nil)
	if d.Allow {
		return
	}
	e := g.event(ctx, id, srv, tool, d)
	e.Outcome = audit.OutcomeDenied
	g.opts.Audit.Record(e)
	g.opts.Metrics.ToolCall(srv, tool, e.Outcome, 0)
}

// toolSpan starts the span of one tool call, under the request's span when there is one.
func (g *Gateway) toolSpan(ctx context.Context) *telemetry.Span {
	if parent := telemetry.SpanFrom(ctx); parent != nil {
		return parent.Child("tools/call", telemetry.SpanInternal)
	}
	h := httpx.HeadersFromContext(ctx)
	return g.opts.Tracer.Start("tools/call", telemetry.SpanInternal, h.Get("Traceparent"), h.Get("Tracestate"))
}

func (g *Gateway) handler(serverName, tool string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		snap := g.opts.Runtime.Current()
		id, _ := auth.FromContext(ctx)
		d := g.decide(ctx, id, serverName, req.Params.Name, req.GetArguments())
		e := g.event(ctx, id, serverName, tool, d)
		span := g.toolSpan(ctx)
		span.SetString("mcp.tool.name", req.Params.Name)
		span.SetString("airlock.server", serverName)
		defer func() {
			elapsed := time.Since(start)
			e.DurationMS = elapsed.Milliseconds()
			g.opts.Audit.Record(e)
			g.opts.Metrics.ToolCall(serverName, tool, e.Outcome, elapsed)
			span.SetString("airlock.outcome", e.Outcome)
			if e.Outcome != audit.OutcomeOK && e.Outcome != audit.OutcomeToolError {
				span.Fail(e.Outcome)
			}
			span.End()
		}()
		if !d.Allow {
			e.Outcome = audit.OutcomeDenied
			return nil, fmt.Errorf("tool '%s' not found: %w", req.Params.Name, server.ErrToolNotFound)
		}
		ticket, denied := snap.Limits.ToolCall(ctx, runtime.Caller(id))
		if denied != nil {
			e.Outcome = audit.OutcomeRateLimited
			e.Error = denied.Code
			g.opts.Metrics.Limited(denied.Code)
			return mcp.NewToolResultError(denied.Code + ": " + denied.Message), nil
		}
		defer ticket.Release()
		b, ok := g.opts.Backends.Get(serverName)
		if !ok {
			e.Outcome = audit.OutcomeBackendUnavailable
			return unavailable(serverName), nil
		}
		upstream := req
		upstream.Params.Name = tool
		call := span.Child("call "+serverName, telemetry.SpanClient)
		res, err := b.Call(httpx.WithTraceparent(ctx, call.Traceparent()), id, upstream)
		if err != nil {
			call.Fail("backend call failed")
		}
		call.End()
		switch {
		case err != nil && ctx.Err() != nil:
			e.Outcome = audit.OutcomeCanceled
			return nil, err
		case errors.Is(err, context.DeadlineExceeded):
			e.Outcome = audit.OutcomeTimeout
			return mcp.NewToolResultError(fmt.Sprintf("server %s timed out", serverName)), nil
		case err != nil:
			e.Outcome = audit.OutcomeBackendUnavailable
			e.Error = err.Error()
			return unavailable(serverName), nil
		case res.IsError:
			e.Outcome = audit.OutcomeToolError
		default:
			e.Outcome = audit.OutcomeOK
		}
		return res, nil
	}
}

func unavailable(serverName string) *mcp.CallToolResult {
	return mcp.NewToolResultError(fmt.Sprintf("server %s is unavailable", serverName))
}

func (g *Gateway) event(ctx context.Context, id *auth.Identity, serverName, tool string, d policy.Decision) audit.Event {
	h := httpx.HeadersFromContext(ctx)
	e := audit.Event{
		Time:      time.Now().UTC(),
		Kind:      audit.KindTool,
		RequestID: h.Get("X-Request-Id"),
		TraceID:   traceID(h.Get("Traceparent")),
		Instance:  g.opts.Instance,
		Server:    serverName,
		Tool:      tool,
		Decision:  "deny",
		Rule:      d.Rule,
	}
	if d.Allow {
		e.Decision = "allow"
	}
	if s := server.ClientSessionFromContext(ctx); s != nil {
		e.SessionID = s.SessionID()
	}
	if id != nil {
		e.Subject, e.Groups, e.Auth = id.Subject, id.Groups, id.Method
	}
	return e
}

func traceID(traceparent string) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) < 4 {
		return ""
	}
	return parts[1]
}
