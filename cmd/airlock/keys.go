package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/admin"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// bootstrapKey issues a new bootstrap admin key straight in the store, for when the first
// one is lost. It needs no running airlock.
func bootstrapKey(ctx context.Context, args []string, stdout, stderr io.Writer, env config.Env) int {
	fs := flag.NewFlagSet("bootstrap-key", flag.ContinueOnError)
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
	key, err := admin.Bootstrap(ctx, st, store.DefaultOrg, true)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, key)
	return 0
}

type groupFlags []string

func (g *groupFlags) String() string { return strings.Join(*g, ",") }

func (g *groupFlags) Set(v string) error {
	*g = append(*g, v)
	return nil
}

// keysNew prints a new API key and the api_keys entry for the config file.
func keysNew(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "new" {
		_, _ = fmt.Fprintln(stderr, "usage: airlock keys new --name <name> [--group <group>]...")
		return 2
	}
	fs := flag.NewFlagSet("keys new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the key's name; its subject is key:<name>")
	var groups groupFlags
	fs.Var(&groups, "group", "a group the key is in, repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *name == "" {
		_, _ = fmt.Fprintln(stderr, "airlock: --name is required")
		return 2
	}
	plain, sha, err := apikey.Generate()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	type fileKey struct {
		Name   string   `yaml:"name"`
		SHA256 string   `yaml:"sha256"`
		Groups []string `yaml:"groups,omitempty,flow"`
	}
	entry, err := yaml.Marshal([]fileKey{{Name: *name, SHA256: sha, Groups: groups}})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "key: %s\n\nAdd this under api_keys in the config file:\n\n%s", plain, indent(string(entry)))
	return 0
}

func indent(s string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "  " + l
		}
	}
	return strings.Join(lines, "")
}
