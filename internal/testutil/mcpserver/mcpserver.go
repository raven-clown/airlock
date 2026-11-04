// Package mcpserver is a small MCP server used by tests, in process and as a child process.
package mcpserver

import (
	"context"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// New returns a server with tools that exercise the paths airlock cares about.
func New(name string) *server.MCPServer {
	s := server.NewMCPServer(name, "test", server.WithToolCapabilities(true))
	s.AddTool(mcp.NewTool("echo", mcp.WithString("text")), func(_ context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(r.GetString("text", "")), nil
	})
	s.AddTool(mcp.NewTool("a__b"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("a__b"), nil
	})
	s.AddTool(mcp.NewTool("bad name"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("bad name"), nil
	})
	s.AddTool(mcp.NewTool("fail"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultError("failed on purpose"), nil
	})
	s.AddTool(mcp.NewTool("crash"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		os.Exit(3)
		return nil, nil
	})
	s.AddTool(mcp.NewTool("wait"), func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		<-ctx.Done()
		return mcp.NewToolResultText("canceled"), nil
	})
	s.AddTool(mcp.NewTool("env", mcp.WithString("name")), func(_ context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(os.Getenv(r.GetString("name", ""))), nil
	})
	s.AddTool(mcp.NewTool("add_tool", mcp.WithString("name")), func(_ context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		added := r.GetString("name", "")
		s.AddTool(mcp.NewTool(added), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(added), nil
		})
		return mcp.NewToolResultText("added " + added), nil
	})
	return s
}
