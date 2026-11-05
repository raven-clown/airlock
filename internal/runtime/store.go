package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// StoreSource builds snapshots from the store. Its version is the org's revision.
type StoreSource struct {
	st      *store.Store
	org     string
	process *config.Config
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
	cfg := *s.process
	cfg.Servers, cfg.Rules, cfg.APIKeys, cfg.RoleBindings = nil, nil, nil, nil
	cfg.Settings = config.Settings{}
	if err := decode(ctx, s, store.KindServers, &cfg.Servers); err != nil {
		return nil, err
	}
	if err := decode(ctx, s, store.KindRules, &cfg.Rules); err != nil {
		return nil, err
	}
	if err := decode(ctx, s, store.KindAPIKeys, &cfg.APIKeys); err != nil {
		return nil, err
	}
	if err := decode(ctx, s, store.KindRoleBindings, &cfg.RoleBindings); err != nil {
		return nil, err
	}
	if err := s.settings(ctx, &cfg.Settings); err != nil {
		return nil, err
	}
	snap, err := Build(&cfg)
	if err != nil {
		return nil, err
	}
	snap.Revision = rev
	return snap, nil
}

// decode appends every row of kind k, decoded, to the slice out points at.
func decode[T any](ctx context.Context, s *StoreSource, k store.Kind, out *[]T) error {
	rows, err := s.st.List(ctx, s.org, k, "", 0)
	if err != nil {
		return err
	}
	for _, r := range rows {
		var v T
		if err := json.Unmarshal(r.Spec, &v); err != nil {
			return fmt.Errorf("%s %q: %w", k, r.Name, err)
		}
		*out = append(*out, v)
	}
	return nil
}

func (s *StoreSource) settings(ctx context.Context, out *config.Settings) error {
	rows, err := s.st.List(ctx, s.org, store.KindSettings, "", 0)
	if err != nil {
		return err
	}
	m := map[string]json.RawMessage{}
	for _, r := range rows {
		m[r.Name] = r.Spec
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	return nil
}
