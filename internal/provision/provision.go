// Package provision writes the resources declared in the config file into the store.
package provision

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// Rows turns the file's resources into store rows by kind and name. Every kind is present.
func Rows(cfg *config.Config) (map[store.Kind]map[string]json.RawMessage, error) {
	out := map[store.Kind]map[string]json.RawMessage{}
	for _, k := range store.Kinds {
		out[k] = map[string]json.RawMessage{}
	}
	add := func(k store.Kind, name string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding %s %q: %w", k, name, err)
		}
		out[k][name] = raw
		return nil
	}
	for _, s := range cfg.Servers {
		if err := add(store.KindServers, s.Name, s); err != nil {
			return nil, err
		}
	}
	for _, r := range cfg.Rules {
		if err := add(store.KindRules, r.Name, r); err != nil {
			return nil, err
		}
	}
	for _, k := range cfg.APIKeys {
		if err := add(store.KindAPIKeys, k.Name, k); err != nil {
			return nil, err
		}
	}
	for _, b := range cfg.RoleBindings {
		if err := add(store.KindRoleBindings, b.Name, b); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(cfg.Settings)
	if err != nil {
		return nil, fmt.Errorf("encoding settings: %w", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("encoding settings: %w", err)
	}
	for name, v := range settings {
		out[store.KindSettings][name] = v
	}
	return out, nil
}

// Apply makes the store's file rows match cfg and reports whether anything changed.
func Apply(ctx context.Context, st *store.Store, org string, cfg *config.Config) (bool, error) {
	rows, err := Rows(cfg)
	if err != nil {
		return false, err
	}
	return st.Provision(ctx, org, rows)
}
