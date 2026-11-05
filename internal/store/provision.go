package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// NameTakenError means the file declares a resource whose name an API row already uses.
type NameTakenError struct {
	Kind Kind
	Name string
}

func (e *NameTakenError) Error() string {
	return fmt.Sprintf("%s %q was created through the admin API; rename one of them", e.Kind, e.Name)
}

type existing struct {
	source string
	spec   string
}

// Provision makes the file rows of every kind match want, in one transaction.
// Kinds missing from want lose all their file rows. API rows are never touched,
// and a name held by one fails the whole call.
func (s *Store) Provision(ctx context.Context, org string, want map[Kind]map[string]json.RawMessage) (bool, error) {
	changed := false
	err := s.write(ctx, org, func(tx *sql.Tx) (bool, error) {
		changed = false
		for _, k := range Kinds {
			c, err := s.provisionKind(ctx, tx, org, k, want[k])
			if err != nil {
				return false, err
			}
			changed = changed || c
		}
		return changed, nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

func (s *Store) provisionKind(ctx context.Context, tx *sql.Tx, org string, k Kind, want map[string]json.RawMessage) (bool, error) {
	t, err := table(k)
	if err != nil {
		return false, err
	}
	have, err := s.existing(ctx, tx, t, org)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", k, err)
	}
	now := millis(s.now().UTC().Truncate(time.Millisecond))
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	changed := false
	for _, name := range names {
		spec, err := compact(want[name])
		if err != nil {
			return false, fmt.Errorf("%s %q: %w", k, name, err)
		}
		cur, ok := have[name]
		switch {
		case ok && cur.source != SourceFile:
			return false, &NameTakenError{Kind: k, Name: name}
		case ok && cur.spec == spec:
			continue
		case ok:
			_, err = tx.ExecContext(ctx, s.q("UPDATE "+t+" SET spec = ?, version = version + 1, updated_at = ? WHERE org_id = ? AND name = ?"), spec, now, org, name)
		default:
			_, err = tx.ExecContext(ctx, s.q("INSERT INTO "+t+" (org_id, "+rowColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)"), org, name, SourceFile, int64(1), spec, now, now)
		}
		if err != nil {
			return false, fmt.Errorf("provisioning %s %q: %w", k, name, err)
		}
		changed = true
	}
	for name, cur := range have {
		if _, keep := want[name]; keep || cur.source != SourceFile {
			continue
		}
		if _, err := tx.ExecContext(ctx, s.q("DELETE FROM "+t+" WHERE org_id = ? AND name = ?"), org, name); err != nil {
			return false, fmt.Errorf("removing %s %q: %w", k, name, err)
		}
		changed = true
	}
	return changed, nil
}

func (s *Store) existing(ctx context.Context, tx *sql.Tx, t, org string) (map[string]existing, error) {
	rows, err := tx.QueryContext(ctx, s.q("SELECT name, source, spec FROM "+t+" WHERE org_id = ?"), org)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]existing{}
	for rows.Next() {
		var name string
		var e existing
		if err := rows.Scan(&name, &e.source, &e.spec); err != nil {
			return nil, err
		}
		out[name] = e
	}
	return out, rows.Err()
}

func compact(raw json.RawMessage) (string, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return "", fmt.Errorf("invalid spec: %w", err)
	}
	return b.String(), nil
}
