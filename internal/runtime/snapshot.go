// Package runtime holds the immutable snapshot every request reads, and swaps it when config changes.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/policy"
	"github.com/raven-clown/airlock/policy/rules"
)

// Snapshot is everything a request needs, built once per config version.
type Snapshot struct {
	Policy         policy.Policy
	Authenticator  *auth.Chain
	Servers        []backend.Config
	AllowedOrigins []string
	Audit          config.Audit
	Stdio          config.StdioConfig
	ListenAddr     string
}

// Source produces snapshots. Version changes whenever Load would return something new.
type Source interface {
	Load(ctx context.Context) (*Snapshot, error)
	Version(ctx context.Context) (string, error)
}

// Build turns a parsed config into a snapshot.
func Build(cfg *config.Config) (*Snapshot, error) {
	p, err := rules.New(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("building policy: %w", err)
	}
	return &Snapshot{
		Policy:         p,
		Authenticator:  auth.NewChain(apikey.New(cfg.APIKeys, time.Now)),
		Servers:        cfg.Servers,
		AllowedOrigins: cfg.Settings.AllowedOrigins,
		Audit:          cfg.Audit,
		Stdio:          cfg.Stdio,
		ListenAddr:     cfg.ListenAddr,
	}, nil
}

// Holder gives readers the current snapshot without locks.
type Holder struct {
	p atomic.Pointer[Snapshot]
}

// NewHolder returns a holder starting at s.
func NewHolder(s *Snapshot) *Holder {
	h := &Holder{}
	h.p.Store(s)
	return h
}

// Current returns the snapshot in use.
func (h *Holder) Current() *Snapshot { return h.p.Load() }

// Swap replaces the snapshot.
func (h *Holder) Swap(s *Snapshot) { h.p.Store(s) }

// WatchOptions tune Watch.
type WatchOptions struct {
	Every  time.Duration
	OnSwap func(*Snapshot)
	Logger *slog.Logger
	// Ready is closed once the starting version has been read.
	Ready chan<- struct{}
}

// Watch reloads from src whenever its version changes, until ctx ends.
// A failed load keeps the current snapshot and is logged once per version.
func Watch(ctx context.Context, src Source, h *Holder, opts WatchOptions) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	last, err := src.Version(ctx)
	if err != nil {
		log.Error("reading config version failed", "error", err)
	}
	if opts.Ready != nil {
		close(opts.Ready)
	}
	ticker := time.NewTicker(opts.Every)
	defer ticker.Stop()
	hup := hangups()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-hup:
		}
		v, err := src.Version(ctx)
		if err != nil {
			log.Error("reading config version failed", "error", err)
			continue
		}
		if v == last {
			continue
		}
		last = v
		s, err := src.Load(ctx)
		if err != nil {
			log.Error("config reload failed", "error", err)
			continue
		}
		h.Swap(s)
		log.Info("config reloaded")
		if opts.OnSwap != nil {
			opts.OnSwap(s)
		}
	}
}
