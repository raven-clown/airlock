// Command airlock is an MCP gateway with login, permissions, audit and rate limits.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/raven-clown/airlock/internal/config"
)

var version = "dev"

const usage = `usage: airlock <command>

commands:
  serve     run the gateway (--config file, --stdio for one local client)
  migrate   apply database migrations and exit (--config file)
  version   print the version
  help      show this help
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, config.OSEnv())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, env config.Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stdin, stdout, stderr, env)
	case "migrate":
		return migrate(ctx, args[1:], stdout, stderr, env)
	case "version":
		_, _ = fmt.Fprintf(stdout, "airlock %s\n", version)
		return 0
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
