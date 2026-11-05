package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/backend"
	_ "github.com/raven-clown/airlock/backend/stdio"
	_ "github.com/raven-clown/airlock/backend/streamable"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/gateway"
	"github.com/raven-clown/airlock/internal/httpx"
	"github.com/raven-clown/airlock/internal/provision"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
)

const (
	reloadEvery     = 2 * time.Second
	shutdownTimeout = 10 * time.Second
)

func serve(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, env config.Env) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to the YAML config file")
	stdio := fs.Bool("stdio", false, "serve one client over stdin and stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logOut := stdout
	if *stdio {
		logOut = stderr
	}
	log := slog.New(slog.NewJSONHandler(logOut, nil))

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
	if _, err := provision.Apply(ctx, st, store.DefaultOrg, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	src := runtime.NewStoreSource(st, store.DefaultOrg, cfg)
	snap, err := src.Load(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	holder := runtime.NewHolder(snap)

	sinks, err := buildSinks(snap.Audit, logOut)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	sinks = append([]audit.Sink{st.AuditSink(store.DefaultOrg)}, sinks...)
	pipe := audit.NewPipeline(sinks, audit.PipelineOptions{BufferSize: snap.Audit.BufferSize, Block: snap.Audit.OnOverflow == "block", Logger: log})

	set := backend.NewSet(backend.Deps{Logger: log, Env: env.Lookup})
	if err := set.Apply(ctx, snap.Servers); err != nil {
		log.Error("starting backends", "error", err)
	}
	instance, _ := os.Hostname()
	gw := gateway.New(gateway.Options{Backends: set, Runtime: holder, Audit: pipe, Logger: log, Instance: instance, Version: version})

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		provision.Watch(ctx, *path, env, st, store.DefaultOrg, provision.WatchOptions{Every: reloadEvery, Logger: log, Process: cfg})
	})
	wg.Go(func() {
		runtime.Watch(ctx, src, holder, runtime.WatchOptions{
			Every:  reloadEvery,
			Logger: log,
			OnSwap: func(s *runtime.Snapshot) {
				if err := set.Apply(ctx, s.Servers); err != nil {
					log.Error("applying backends", "error", err)
				}
			},
		})
	})
	wg.Go(func() { runRetention(ctx, st, store.DefaultOrg, time.Hour, cfg.Audit.Retention, time.Now, log) })

	// The store closes last, after the loops stop and the audit pipeline flushes into it.
	defer func() {
		cancel()
		wg.Wait()
		_ = set.Close()
		closeCtx, cancelClose := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancelClose()
		_ = pipe.Close(closeCtx)
	}()

	if *stdio {
		id := &auth.Identity{Subject: snap.Stdio.Identity, Groups: snap.Stdio.Groups, Method: "stdio"}
		if err := gw.ServeStdio(ctx, stdin, stdout, id); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			log.Error("stdio server stopped", "error", err)
			return 1
		}
		return 0
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", snap.ListenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	mcp := httpx.CheckOrigin(func() []string { return holder.Current().Settings.AllowedOrigins }, gw.HTTPHandler())
	srv := &http.Server{Handler: httpx.NewMux(mcp, ready(holder, set, st, log)), ReadHeaderTimeout: 10 * time.Second}
	log.Info("listening", "addr", ln.Addr().String(), "version", version)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Error("server stopped", "error", err)
		return 1
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("shutdown", "error", err)
	}
	return 0
}

// buildSinks creates the configured audit sinks. The stdout sink writes to the
// log stream, which is stderr in stdio mode so the protocol stream stays clean.
func buildSinks(cfg config.Audit, logOut io.Writer) ([]audit.Sink, error) {
	var sinks []audit.Sink
	for _, s := range cfg.Sinks {
		if s.Kind == "stdout" {
			sinks = append(sinks, audit.NewStdoutSink(logOut))
			continue
		}
		f, ok := audit.LookupSink(s.Kind)
		if !ok {
			return nil, fmt.Errorf("unknown audit sink %q", s.Kind)
		}
		raw, err := json.Marshal(map[string]string{"path": s.Path})
		if err != nil {
			return nil, err
		}
		sink, err := f(raw)
		if err != nil {
			return nil, fmt.Errorf("audit sink %s: %w", s.Kind, err)
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// ready reports whether airlock can serve. /readyz shows the error to anyone, so a
// store error, which can name the database host and user, only goes to the log.
func ready(holder *runtime.Holder, set *backend.Set, st *store.Store, log *slog.Logger) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			log.Error("store is not reachable", "error", err)
			return errors.New("store unavailable")
		}
		for _, s := range holder.Current().Servers {
			if !s.Required {
				continue
			}
			b, ok := set.Get(s.Name)
			if !ok || !b.Status().Up() {
				return fmt.Errorf("backend %s is not up", s.Name)
			}
		}
		return nil
	}
}

// loadConfig reads path, or uses the defaults when path is empty.
func loadConfig(path string, env config.Env) (*config.Config, error) {
	if path == "" {
		return config.Parse(nil, env)
	}
	return config.Load(path, env)
}
