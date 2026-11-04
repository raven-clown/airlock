package gateway

import (
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/internal/naming"
)

// Refresh rebuilds the catalog from every backend's last known tools.
func (g *Gateway) Refresh() {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	var tools []server.ServerTool
	for _, b := range g.opts.Backends.All() {
		for _, t := range b.Tools() {
			pt, ok := prefixed(b.Name(), t, g.log)
			if !ok {
				continue
			}
			tools = append(tools, server.ServerTool{Tool: pt, Handler: g.handler(b.Name(), t.Name)})
		}
	}
	g.mcp.SetTools(tools...)
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
