// Package store keeps airlock's state in SQLite or Postgres.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Registers the sqlite driver.
	_ "modernc.org/sqlite"
)

// DefaultOrg is the only org until organisations ship.
const DefaultOrg = "default"

// Errors returned by the store.
var (
	ErrNotFound        = errors.New("not found")
	ErrExists          = errors.New("already exists")
	ErrVersionConflict = errors.New("version conflict")
	ErrManagedByFile   = errors.New("managed by the config file")
	ErrSchemaTooNew    = errors.New("database schema is newer than this airlock")
)

// Store is an open database.
type Store struct {
	db  *sql.DB
	d   dialect
	now func() time.Time
}

// Open connects to the database and applies migrations. driver is sqlite or postgres.
func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	var d dialect
	switch driver {
	case "sqlite":
		d = sqliteDialect
		if err := createPrivate(sqlitePath(dsn)); err != nil {
			return nil, err
		}
		dsn = sqliteDSN(dsn)
	case "postgres":
		d = postgresDialect
	default:
		return nil, fmt.Errorf("unknown storage driver %q", driver)
	}
	db, err := sql.Open(d.driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", driver, err)
	}
	if d == sqliteDialect {
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db, d: d, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// sqlitePath returns the file a sqlite DSN names, or "" for an in-memory database.
func sqlitePath(dsn string) string {
	path, query, _ := strings.Cut(strings.TrimPrefix(dsn, "file:"), "?")
	if path == "" || path == ":memory:" || strings.Contains(query, "mode=memory") {
		return ""
	}
	return path
}

// createPrivate creates a new database file readable only by its owner, since rows
// can hold secrets from the config file. SQLite gives its WAL files the same mode.
func createPrivate(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating the database file: %w", err)
	}
	return f.Close()
}

func sqliteDSN(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) q(query string) string { return s.d.rebind(query) }

func millis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// Revision returns the org's revision, which moves on every change to its resources.
func (s *Store) Revision(ctx context.Context, org string) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, s.q("SELECT value FROM revision WHERE org_id = ?"), org).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading revision: %w", err)
	}
	return v, nil
}

// write runs fn in a transaction that holds the org's revision row, and bumps the
// revision when fn reports a change. Holding the row serializes writers per org on Postgres.
func (s *Store) write(ctx context.Context, org string, fn func(tx *sql.Tx) (bool, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.q("INSERT INTO revision (org_id, value) VALUES (?, 0) ON CONFLICT DO NOTHING"), org); err != nil {
		return fmt.Errorf("locking revision: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q("UPDATE revision SET value = value WHERE org_id = ?"), org); err != nil {
		return fmt.Errorf("locking revision: %w", err)
	}
	changed, err := fn(tx)
	if err != nil {
		return err
	}
	if changed {
		if _, err := tx.ExecContext(ctx, s.q("UPDATE revision SET value = value + 1 WHERE org_id = ?"), org); err != nil {
			return fmt.Errorf("bumping revision: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}
