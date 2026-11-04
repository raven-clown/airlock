// Command testserver serves the test MCP server over stdio.
package main

import (
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/server"

	"github.com/raven-clown/airlock/internal/testutil/mcpserver"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--stderr" {
		for i := 0; i < 150; i++ {
			fmt.Fprintf(os.Stderr, "line %d\n", i)
		}
	}
	if err := server.ServeStdio(mcpserver.New("testserver")); err != nil {
		os.Exit(1)
	}
}
