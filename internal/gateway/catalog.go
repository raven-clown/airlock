package gateway

import (
	"log/slog"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/internal/naming"
)

// Refresh rebuilds the catalog from every backend's last known tools.
func (g *Gateway) Refresh() {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	var tools []server.ServerTool
	known := map[string]bool{}
	for _, b := range g.opts.Backends.All() {
		known[b.Name()] = true
		for _, t := range b.Tools() {
			pt, ok := prefixed(b.Name(), t, g.log)
			if !ok {
				continue
			}
			known[pt.Name] = true
			tools = append(tools, server.ServerTool{Tool: pt, Handler: g.handler(b.Name(), t.Name)})
		}
	}
	g.known.Store(&known)
	g.mcp.SetTools(tools...)
}

// Known reports whether the catalog has the server, and the tool on it when tool is set.
func (g *Gateway) Known(serverName, tool string) bool {
	known := g.known.Load()
	if known == nil {
		return false
	}
	if tool == "" {
		return (*known)[serverName]
	}
	name, err := naming.Join(serverName, tool)
	return err == nil && (*known)[name]
}

// Tool is one catalog entry.
type Tool struct {
	Name   string
	Server string
	Tool   mcp.Tool
}

// Tools returns the catalog sorted by name.
func (g *Gateway) Tools() []Tool {
	all := g.mcp.ListTools()
	out := make([]Tool, 0, len(all))
	for name, st := range all {
		srv, _, _ := naming.Split(name)
		out = append(out, Tool{Name: name, Server: srv, Tool: st.Tool})
	}
	slices.SortFunc(out, func(a, b Tool) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// prefixed renames t for the catalog. Tools mcp-go would reject are skipped,
// so one bad upstream tool cannot take the gateway down.
func prefixed(serverName string, t mcp.Tool, log *slog.Logger) (mcp.Tool, bool) {
	name, err := naming.Join(serverName, t.Name)
	if err != nil {
		log.Warn("skipping tool", "backend", serverName, "tool", t.Name, "error", err)
		return mcp.Tool{}, false
	}
	t.Name = name
	if err := mcp.ValidateParamHeaderAnnotations(&t); err != nil {
		log.Warn("skipping tool", "backend", serverName, "tool", t.Name, "error", err)
		return mcp.Tool{}, false
	}
	return t, true
}
