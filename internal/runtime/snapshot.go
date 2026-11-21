// Package runtime holds the immutable snapshot every request reads, and swaps it when config changes.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/auth/oidc"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/policy"
	"github.com/raven-clown/airlock/policy/rules"
	"github.com/raven-clown/airlock/ratelimit"
)

// Snapshot is everything a request needs, built once per config version.
type Snapshot struct {
	Policy        policy.Policy
	Authenticator *auth.Chain
	// OIDC is the token authenticator, nil when settings.oidc is not set.
	OIDC         *oidc.Authenticator
	Limits       *limits.Limiter
	Servers      []backend.Config
	Settings     config.Settings
	RoleBindings []config.RoleBinding
	Audit        config.Audit
	Stdio        config.StdioConfig
	ListenAddr   string
	// Revision is the store revision the snapshot was built from.
	Revision int64
}

// Source produces snapshots. Version changes whenever Load would return something new.
type Source interface {
	Load(ctx context.Context) (*Snapshot, error)
	Version(ctx context.Context) (string, error)
}

// Build turns a parsed config into a snapshot with fresh limit counters.
func Build(cfg *config.Config) (*Snapshot, error) { return BuildFrom(cfg, nil) }

// BuildFrom turns a parsed config into a snapshot. It keeps prev's limit counters, and prev's
// OIDC authenticator when the OIDC settings are the same, so a reload neither resets what
// callers have used nor fetches the issuer's keys again.
func BuildFrom(cfg *config.Config, prev *Snapshot) (*Snapshot, error) {
	p, err := rules.New(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("building policy: %w", err)
	}
	lc, err := cfg.LimitsConfig()
	if err != nil {
		return nil, fmt.Errorf("building limits: %w", err)
	}
	var lim *limits.Limiter
	if prev != nil && prev.Limits != nil {
		lim = prev.Limits.WithConfig(lc)
	} else {
		lim = limits.New(lc, ratelimit.NewMemoryStore(), time.Now)
	}
	auths := []auth.Authenticator{apikey.New(cfg.APIKeys, time.Now)}
	var oa *oidc.Authenticator
	if o := cfg.Settings.OIDC; o != nil {
		oc := oidc.Config{Issuer: o.Issuer, Audience: o.Audience, JWKSURL: o.JWKSURL,
			SubjectClaim: o.SubjectClaim, GroupsClaim: o.GroupsClaim, ProfileClaim: o.ProfileClaim}
		if prev != nil && prev.OIDC != nil && prev.OIDC.Same(oc) {
			oa = prev.OIDC
		} else if oa, err = oidc.New(oc); err != nil {
			return nil, fmt.Errorf("building oidc: %w", err)
		}
		auths = append(auths, oa)
	}
	return &Snapshot{
		Policy:        p,
		Authenticator: auth.NewChain(auths...),
		OIDC:          oa,
		Limits:        lim,
		Servers:       cfg.Servers,
		Settings:      cfg.Settings,
		RoleBindings:  cfg.RoleBindings,
		Audit:         cfg.Audit,
		Stdio:         cfg.Stdio,
		ListenAddr:    cfg.ListenAddr,
	}, nil
}

var roleRank = map[string]int{config.RoleMember: 1, config.RoleViewer: 2, config.RoleAdmin: 3}

// Role returns the highest admin API role a role binding gives id, or "" for none.
func (s *Snapshot) Role(id *auth.Identity) string {
	subjects := policy.Subjects(id)
	best := ""
	for _, b := range s.RoleBindings {
		if roleRank[b.Role] <= roleRank[best] {
			continue
		}
		for _, sub := range b.Subjects {
			if slices.Contains(subjects, sub) {
				best = b.Role
				break
			}
		}
	}
	return best
}

// HasRole reports whether role is at least need.
func HasRole(role, need string) bool { return roleRank[role] >= roleRank[need] && roleRank[need] > 0 }

// Caller returns who id's calls are counted against.
func Caller(id *auth.Identity) limits.Caller {
	if id == nil {
		return limits.Caller{}
	}
	return limits.Caller{Subject: id.Subject, Key: id.KeyName, Groups: id.Groups, ClaimProfile: id.Profile}
}

// Holder gives readers the current snapshot without locks.
type Holder struct {
	p atomic.Pointer[Snapshot]

	mu    sync.Mutex
	state ReloadState
}

// ReloadState is how the last reload went, for /status.
type ReloadState struct {
	// At is when the last reload was tried, zero before the first.
	At time.Time `json:"at,omitzero"`
	// Error is why the last reload failed, empty when it worked.
	Error string `json:"error,omitempty"`
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

// State returns how the last reload went.
func (h *Holder) State() ReloadState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

func (h *Holder) record(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = ReloadState{At: time.Now().UTC()}
	if err != nil {
		h.state.Error = err.Error()
	}
}

// WatchOptions tune Watch.
type WatchOptions struct {
	Every  time.Duration
	OnSwap func(*Snapshot)
	// OnResult is told whether each reload that was tried worked.
	OnResult func(ok bool)
	Logger   *slog.Logger
	// Ready is closed once the starting version has been read.
	Ready chan<- struct{}
	// Start is the version the holder's snapshot was built from. With it set, a change
	// made before the first check is loaded by that check instead of taken as the start.
	Start string
}

// Reloader swaps in a new snapshot when the source's version moves, on its own loop and when
// asked after a write.
type Reloader struct {
	src  Source
	h    *Holder
	opts WatchOptions
	log  *slog.Logger

	mu   sync.Mutex
	last string
	seen bool
}

// NewReloader returns a reloader for src into h.
func NewReloader(src Source, h *Holder, opts WatchOptions) *Reloader {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Reloader{src: src, h: h, opts: opts, log: log, last: opts.Start, seen: opts.Start != ""}
}

// StartVersion is the WatchOptions.Start of a snapshot from a StoreSource.
func StartVersion(s *Snapshot) string { return strconv.FormatInt(s.Revision, 10) }

// Check reloads when the version has moved since the last check, and reports whether it
// swapped. A failed load keeps the current snapshot and is not tried again until the
// version moves.
func (r *Reloader) Check(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.src.Version(ctx)
	if err != nil {
		return false, fmt.Errorf("reading config version: %w", err)
	}
	if r.seen && v == r.last {
		return false, nil
	}
	first := !r.seen
	r.last, r.seen = v, true
	if first {
		return false, nil
	}
	s, err := r.src.Load(ctx)
	r.h.record(err)
	if r.opts.OnResult != nil {
		r.opts.OnResult(err == nil)
	}
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReload, err)
	}
	r.h.Swap(s)
	r.log.Info("config reloaded", "version", v)
	if r.opts.OnSwap != nil {
		r.opts.OnSwap(s)
	}
	return true, nil
}

// ErrReload wraps a load that failed after the version moved.
var ErrReload = errors.New("loading the changed config")

// Run checks every opts.Every until ctx ends. The first check only reads the version the
// current snapshot was built from.
func (r *Reloader) Run(ctx context.Context) {
	r.logCheck(ctx)
	if r.opts.Ready != nil {
		close(r.opts.Ready)
	}
	ticker := time.NewTicker(r.opts.Every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.logCheck(ctx)
	}
}

func (r *Reloader) logCheck(ctx context.Context) {
	_, err := r.Check(ctx)
	switch {
	case err == nil || ctx.Err() != nil:
	case errors.Is(err, ErrReload):
		r.log.Error("config reload failed", "error", err)
	default:
		r.log.Error("reading config version failed", "error", err)
	}
}

// Watch reloads from src whenever its version changes, until ctx ends.
func Watch(ctx context.Context, src Source, h *Holder, opts WatchOptions) {
	NewReloader(src, h, opts).Run(ctx)
}
