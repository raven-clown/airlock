// Command airlock is an MCP gateway with login, permissions, audit and rate limits.
package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

const usage = `usage: airlock <command>

commands:
  version   print the version
  help      show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
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
