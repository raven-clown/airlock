package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Kind names a resource table.
type Kind string

// Resource kinds. Each is its own table with the same columns.
const (
	KindServers      Kind = "servers"
	KindRules        Kind = "rules"
	KindAPIKeys      Kind = "api_keys"
	KindRoleBindings Kind = "role_bindings"
	KindSettings     Kind = "settings"
)

// Kinds lists every resource kind.
var Kinds = []Kind{KindServers, KindRules, KindAPIKeys, KindRoleBindings, KindSettings}

// Where a row came from.
const (
	SourceFile = "file"
	SourceAPI  = "api"
)

// Row is one stored resource. Spec is the resource itself as JSON.
type Row struct {
	Name      string
	Source    string
	Version   int64
	Spec      json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// table returns k's table name. Only names from Kinds reach SQL.
func table(k Kind) (string, error) {
	for _, known := range Kinds {
		if k == known {
			return string(k), nil
		}
	}
	return "", fmt.Errorf("unknown resource kind %q", k)
}

const rowColumns = "name, source, version, spec, created_at, updated_at"

type scanner interface {
	Scan(dest ...any) error
}

func scanRow(sc scanner) (Row, error) {
	var r Row
	var spec string
	var created, updated int64
	if err := sc.Scan(&r.Name, &r.Source, &r.Version, &spec, &created, &updated); err != nil {
		return Row{}, err
	}
	r.Spec = json.RawMessage(spec)
	r.CreatedAt, r.UpdatedAt = fromMillis(created), fromMillis(updated)
	return r, nil
}

// Get returns one row.
func (s *Store) Get(ctx context.Context, org string, k Kind, name string) (Row, error) {
	t, err := table(k)
	if err != nil {
		return Row{}, err
	}
	r, err := scanRow(s.db.QueryRowContext(ctx, s.q("SELECT "+rowColumns+" FROM "+t+" WHERE org_id = ? AND name = ?"), org, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, fmt.Errorf("%s %q: %w", k, name, ErrNotFound)
	}
	if err != nil {
		return Row{}, fmt.Errorf("reading %s %q: %w", k, name, err)
	}
	return r, nil
}

// List returns rows in name order, starting after the name after. limit <= 0 means all.
func (s *Store) List(ctx context.Context, org string, k Kind, after string, limit int) ([]Row, error) {
	t, err := table(k)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + rowColumns + " FROM " + t + " WHERE org_id = ? AND name > ? ORDER BY name"
	args := []any{org, after}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", k, err)
	}
	defer func() { _ = rows.Close() }()
	out := []Row{}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", k, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing %s: %w", k, err)
	}
	return out, nil
}

// Create adds a row owned by the API.
func (s *Store) Create(ctx context.Context, org string, k Kind, name string, spec json.RawMessage) (Row, error) {
	t, err := table(k)
	if err != nil {
		return Row{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	r := Row{Name: name, Source: SourceAPI, Version: 1, Spec: spec, CreatedAt: now, UpdatedAt: now}
	err = s.write(ctx, org, func(tx *sql.Tx) (bool, error) {
		if _, _, err := lockRow(ctx, s, tx, t, org, name); err == nil {
			return false, fmt.Errorf("%s %q: %w", k, name, ErrExists)
		} else if !errors.Is(err, ErrNotFound) {
			return false, err
		}
		_, err := tx.ExecContext(ctx, s.q("INSERT INTO "+t+" (org_id, "+rowColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)"),
			org, name, SourceAPI, int64(1), string(spec), millis(now), millis(now))
		if err != nil {
			return false, fmt.Errorf("creating %s %q: %w", k, name, err)
		}
		return true, nil
	})
	if err != nil {
		return Row{}, err
	}
	return r, nil
}

// lockRow reads a row's source and version inside tx.
func lockRow(ctx context.Context, s *Store, tx *sql.Tx, t, org, name string) (source string, version int64, err error) {
	err = tx.QueryRowContext(ctx, s.q("SELECT source, version FROM "+t+" WHERE org_id = ? AND name = ?"), org, name).Scan(&source, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	return source, version, err
}

// checkWritable returns the error an API write to a row gets, or nil.
func checkWritable(k Kind, name, source string, have, want int64, err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fmt.Errorf("%s %q: %w", k, name, ErrNotFound)
	case err != nil:
		return fmt.Errorf("reading %s %q: %w", k, name, err)
	case source == SourceFile:
		return fmt.Errorf("%s %q: %w", k, name, ErrManagedByFile)
	case have != want:
		return fmt.Errorf("%s %q is at version %d, not %d: %w", k, name, have, want, ErrVersionConflict)
	}
	return nil
}

// Update replaces the spec of an API row whose version is version, and bumps the version.
func (s *Store) Update(ctx context.Context, org string, k Kind, name string, version int64, spec json.RawMessage) (Row, error) {
	t, err := table(k)
	if err != nil {
		return Row{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	var r Row
	err = s.write(ctx, org, func(tx *sql.Tx) (bool, error) {
		source, have, err := lockRow(ctx, s, tx, t, org, name)
		if err := checkWritable(k, name, source, have, version, err); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, s.q("UPDATE "+t+" SET spec = ?, version = ?, updated_at = ? WHERE org_id = ? AND name = ?"),
			string(spec), version+1, millis(now), org, name); err != nil {
			return false, fmt.Errorf("updating %s %q: %w", k, name, err)
		}
		r, err = scanRow(tx.QueryRowContext(ctx, s.q("SELECT "+rowColumns+" FROM "+t+" WHERE org_id = ? AND name = ?"), org, name))
		if err != nil {
			return false, fmt.Errorf("reading %s %q: %w", k, name, err)
		}
		return true, nil
	})
	if err != nil {
		return Row{}, err
	}
	return r, nil
}

// Delete removes an API row whose version is version.
func (s *Store) Delete(ctx context.Context, org string, k Kind, name string, version int64) error {
	t, err := table(k)
	if err != nil {
		return err
	}
	return s.write(ctx, org, func(tx *sql.Tx) (bool, error) {
		source, have, err := lockRow(ctx, s, tx, t, org, name)
		if err := checkWritable(k, name, source, have, version, err); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, s.q("DELETE FROM "+t+" WHERE org_id = ? AND name = ?"), org, name); err != nil {
			return false, fmt.Errorf("deleting %s %q: %w", k, name, err)
		}
		return true, nil
	})
}
