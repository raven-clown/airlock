// Package testutil holds helpers shared by tests.
package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
)

// BuildTestServer builds the stdio test MCP server into dir and returns its path.
func BuildTestServer(dir string) (string, error) {
	name := "testserver"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(dir, name)
	//nolint:gosec // builds a fixed package into a test temp dir
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", out, "github.com/raven-clown/airlock/internal/testutil/mcpserver/cmd/testserver")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building test server: %w: %s", err, b)
	}
	return out, nil
}
