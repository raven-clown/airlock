package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// StoreSource builds snapshots from the store. Its version is the org's revision.
type StoreSource struct {
	st      *store.Store
	org     string
	process *config.Config

	mu   sync.Mutex
	last *Snapshot
}

// NewStoreSource returns a source reading org's resources from st. Process settings
// such as listen_addr come from process, since they only change on restart.
func NewStoreSource(st *store.Store, org string, process *config.Config) *StoreSource {
	return &StoreSource{st: st, org: org, process: process}
}

// Version implements Source.
func (s *StoreSource) Version(ctx context.Context) (string, error) {
	rev, err := s.st.Revision(ctx, s.org)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(rev, 10), nil
}

// Load implements Source. The revision is read first, so a write that lands
// during the load moves it again and triggers another load.
func (s *StoreSource) Load(ctx context.Context) (*Snapshot, error) {
	rev, err := s.st.Revision(ctx, s.org)
	if err != nil {
		return nil, err
	}
	cfg, err := s.Config(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := BuildFrom(cfg, s.last)
	if err != nil {
		return nil, err
	}
	snap.Revision = rev
	s.last = snap
	return snap, nil
}

// Config returns the process settings with every resource in the store, checked and with
// defaults filled in the way the file loader does it.
func (s *StoreSource) Config(ctx context.Context) (*config.Config, error) {
	return s.ConfigWith(ctx)
}

// Change is one row a write would add, replace or, with a nil Spec, remove.
type Change struct {
	Kind store.Kind
	Name string
	Spec json.RawMessage
}

// ConfigWith returns the config the store would hold after changes, checked as Config is.
// The admin API calls it before a write, so a write that would leave a config that does not
// load is refused instead of stored.
func (s *StoreSource) ConfigWith(ctx context.Context, changes ...Change) (*config.Config, error) {
	rows := map[store.Kind]map[string]json.RawMessage{}
	for _, k := range store.Kinds {
		list, err := s.st.List(ctx, s.org, k, "", 0)
		if err != nil {
			return nil, err
		}
		rows[k] = map[string]json.RawMessage{}
		for _, r := range list {
			rows[k][r.Name] = r.Spec
		}
	}
	for _, c := range changes {
		if c.Spec == nil {
			delete(rows[c.Kind], c.Name)
			continue
		}
		rows[c.Kind][c.Name] = c.Spec
	}
	cfg := *s.process
	cfg.Servers, cfg.Rules, cfg.APIKeys, cfg.RoleBindings, cfg.Profiles, cfg.ProfileBindings = nil, nil, nil, nil, nil, nil
	cfg.Settings = config.Settings{}
	if err := decode(rows, store.KindServers, &cfg.Servers); err != nil {
		return nil, err
	}
	if err := decode(rows, store.KindRules, &cfg.Rules); err != nil {
		return nil, err
	}
	if err := decode(rows, store.KindAPIKeys, &cfg.APIKeys); err != nil {
		return nil, err
	}
	if err := decode(rows, store.KindRoleBindings, &cfg.RoleBindings); err != nil {
		return nil, err
	}
	if err := decode(rows, store.KindProfiles, &cfg.Profiles); err != nil {
		return nil, err
	}
	if err := decode(rows, store.KindProfileBindings, &cfg.ProfileBindings); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rows[store.KindSettings])
	if err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg.Settings); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if err := config.Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// decode appends every row of kind k, decoded in name order, to the slice out points at.
func decode[T any](rows map[store.Kind]map[string]json.RawMessage, k store.Kind, out *[]T) error {
	for _, name := range slices.Sorted(maps.Keys(rows[k])) {
		var v T
		if err := json.Unmarshal(rows[k][name], &v); err != nil {
			return fmt.Errorf("%s %q: %w", k, name, err)
		}
		*out = append(*out, v)
	}
	return nil
}
