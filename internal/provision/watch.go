package provision

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// WatchOptions tune Watch.
type WatchOptions struct {
	Every  time.Duration
	Logger *slog.Logger
	// Ready is closed once the starting file has been read.
	Ready chan<- struct{}
	// Process is the config airlock started with. Process settings only change on restart.
	Process *config.Config
}

// Watch provisions the file at path again whenever its content changes or SIGHUP
// arrives, until ctx ends. A file that fails to load or apply changes nothing.
func Watch(ctx context.Context, path string, env config.Env, st *store.Store, org string, opts WatchOptions) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	if path == "" {
		if opts.Ready != nil {
			close(opts.Ready)
		}
		return
	}
	last, err := fileHash(path)
	if err != nil {
		log.Error("reading config failed", "error", err)
	}
	if opts.Ready != nil {
		close(opts.Ready)
	}
	ticker := time.NewTicker(opts.Every)
	defer ticker.Stop()
	hup := hangups()
	for {
		force := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-hup:
			force = true
		}
		h, err := fileHash(path)
		if err != nil {
			log.Error("reading config failed", "error", err)
			continue
		}
		if h == last && !force {
			continue
		}
		last = h
		cfg, err := config.Load(path, env)
		if err == nil {
			_, err = Apply(ctx, st, org, cfg)
		}
		if err != nil {
			log.Error("config reload failed", "error", err)
			continue
		}
		log.Info("config file provisioned")
		if keys := processChanges(opts.Process, cfg); len(keys) > 0 {
			log.Warn("restart airlock to apply", "keys", keys)
		}
	}
}

func fileHash(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("reading config: %w", err)
	}
	return sha256.Sum256(data), nil
}

func processChanges(was, now *config.Config) []string {
	if was == nil {
		return nil
	}
	var keys []string
	if was.ListenAddr != now.ListenAddr {
		keys = append(keys, "listen_addr")
	}
	if was.Storage != now.Storage {
		keys = append(keys, "storage")
	}
	if !reflect.DeepEqual(was.Stdio, now.Stdio) {
		keys = append(keys, "stdio")
	}
	if !reflect.DeepEqual(was.Audit, now.Audit) {
		keys = append(keys, "audit")
	}
	return keys
}
