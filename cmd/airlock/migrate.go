package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

func migrate(ctx context.Context, args []string, stdout, stderr io.Writer, env config.Env) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to the YAML config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*path, env)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	st, err := store.Open(ctx, cfg.Storage.Driver, cfg.Storage.DSN)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	v, err := st.SchemaVersion(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "schema version %d\n", v)
	return 0
}
