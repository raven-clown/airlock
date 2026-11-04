package backend

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// Set runs the configured backends and keeps them in step with config changes.
type Set struct {
	deps Deps

	mu       sync.RWMutex
	backends map[string]Backend
	configs  map[string]Config

	cbMu      sync.RWMutex
	callbacks []func()
}

// NewSet returns an empty set.
func NewSet(deps Deps) *Set {
	return &Set{deps: deps, backends: map[string]Backend{}, configs: map[string]Config{}}
}

// OnChange registers fn to run when backends are added, removed or restarted, or when their tools change.
func (s *Set) OnChange(fn func()) {
	s.cbMu.Lock()
	defer s.cbMu.Unlock()
	s.callbacks = append(s.callbacks, fn)
}

func (s *Set) fire() {
	s.cbMu.RLock()
	cbs := append([]func(){}, s.callbacks...)
	s.cbMu.RUnlock()
	for _, fn := range cbs {
		fn()
	}
}

// Apply starts new backends, stops removed ones and restarts changed ones.
func (s *Set) Apply(ctx context.Context, cfgs []Config) error {
	want := make(map[string]Config, len(cfgs))
	for _, c := range cfgs {
		want[c.Name] = c
	}
	changed := false
	var errs []error

	s.mu.Lock()
	for name, b := range s.backends {
		if c, ok := want[name]; !ok || !reflect.DeepEqual(c, s.configs[name]) {
			errs = append(errs, b.Close())
			delete(s.backends, name)
			delete(s.configs, name)
			changed = true
		}
	}
	for _, c := range cfgs {
		if _, ok := s.backends[c.Name]; ok {
			continue
		}
		f, ok := lookup(c.Transport)
		if !ok {
			errs = append(errs, fmt.Errorf("backend %q: unknown transport %q", c.Name, c.Transport))
			continue
		}
		b, err := f(c, s.deps)
		if err != nil {
			errs = append(errs, fmt.Errorf("backend %q: %w", c.Name, err))
			continue
		}
		b.OnToolsChanged(s.fire)
		if err := b.Start(ctx); err != nil {
			errs = append(errs, fmt.Errorf("backend %q: %w", c.Name, err))
		}
		s.backends[c.Name] = b
		s.configs[c.Name] = c
		changed = true
	}
	s.mu.Unlock()

	if changed {
		s.fire()
	}
	return errors.Join(errs...)
}

// Get returns the backend called name.
func (s *Set) Get(name string) (Backend, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.backends[name]
	return b, ok
}

// All returns every backend, sorted by name.
func (s *Set) All() []Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Backend, 0, len(s.backends))
	for _, b := range s.backends {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Close stops every backend.
func (s *Set) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for name, b := range s.backends {
		errs = append(errs, b.Close())
		delete(s.backends, name)
		delete(s.configs, name)
	}
	return errors.Join(errs...)
}
