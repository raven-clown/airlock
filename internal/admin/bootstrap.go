package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/store"
)

// Names of what the first start creates.
const (
	BootstrapKey     = "bootstrap"
	BootstrapBinding = "bootstrap-admin"
	EveryoneBinding  = "everyone"
)

// Bootstrap gives a store with no role bindings an admin API key named bootstrap, a binding
// that makes it admin, and a binding of every caller to member. It returns the key, or ""
// when the store already had role bindings. With force it issues a new key in any case, for
// a lost one.
func Bootstrap(ctx context.Context, st *store.Store, org string, force bool) (string, error) {
	bindings, err := st.List(ctx, org, store.KindRoleBindings, "", 1)
	if err != nil {
		return "", err
	}
	if len(bindings) > 0 && !force {
		return "", nil
	}
	plain, sha, err := apikey.Generate()
	if err != nil {
		return "", err
	}
	ev := func(action, resource string) audit.Event {
		return audit.Event{Time: time.Now().UTC(), Kind: audit.KindAdmin, Action: action, Resource: resource,
			Subject: "airlock", Auth: "bootstrap", Outcome: audit.OutcomeOK}
	}
	key, err := json.Marshal(apikey.Key{Name: BootstrapKey, SHA256: sha})
	if err != nil {
		return "", err
	}
	row, err := st.Get(ctx, org, store.KindAPIKeys, BootstrapKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		_, err = st.Create(ctx, org, store.KindAPIKeys, BootstrapKey, key, ev("create", "api-keys/"+BootstrapKey))
	case err == nil && row.Source == store.SourceFile:
		return "", fmt.Errorf("api key %q is declared in the config file; remove it there or declare role_bindings", BootstrapKey)
	case err == nil:
		_, err = st.Update(ctx, org, store.KindAPIKeys, BootstrapKey, row.Version, key, ev("rotate", "api-keys/"+BootstrapKey))
	}
	if err != nil {
		return "", fmt.Errorf("storing the bootstrap key: %w", err)
	}
	for _, b := range []config.RoleBinding{
		{Name: BootstrapBinding, Subjects: []string{"key:" + BootstrapKey}, Role: config.RoleAdmin},
		{Name: EveryoneBinding, Subjects: []string{"*"}, Role: config.RoleMember},
	} {
		if b.Name == EveryoneBinding && len(bindings) > 0 {
			continue
		}
		if _, err := st.Get(ctx, org, store.KindRoleBindings, b.Name); err == nil {
			continue
		}
		spec, err := json.Marshal(b)
		if err != nil {
			return "", err
		}
		if _, err := st.Create(ctx, org, store.KindRoleBindings, b.Name, spec, ev("create", "role-bindings/"+b.Name)); err != nil {
			return "", fmt.Errorf("storing role binding %s: %w", b.Name, err)
		}
	}
	return plain, nil
}
