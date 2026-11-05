package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations
var migrations embed.FS

// LatestSchema is the newest schema version this binary knows.
var LatestSchema = mustLatest()

type migration struct {
	version int
	sql     string
}

func loadMigrations(engine string) ([]migration, error) {
	dir := "migrations/" + engine
	entries, err := fs.ReadDir(migrations, dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok || !strings.HasSuffix(e.Name(), ".sql") {
			return nil, fmt.Errorf("bad migration name %s", e.Name())
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("bad migration name %s", e.Name())
		}
		data, err := fs.ReadFile(migrations, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, sql: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func mustLatest() int {
	ms, err := loadMigrations(sqliteDialect.name)
	if err != nil || len(ms) == 0 {
		panic(fmt.Sprintf("embedded migrations: %v", err))
	}
	return ms[len(ms)-1].version
}

// migrateLockID is the Postgres advisory lock that keeps replicas from migrating at once.
const migrateLockID = 7413020

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations(s.d.name)
	if err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", s.d.name, err)
	}
	defer func() { _ = conn.Close() }()
	if s.d == postgresDialect {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrateLockID); err != nil {
			return fmt.Errorf("locking migrations: %w", err)
		}
		defer func() {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLockID)
		}()
	}
	if _, err := conn.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)"); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}
	current, err := schemaVersion(ctx, conn)
	if err != nil {
		return err
	}
	latest := ms[len(ms)-1].version
	if current > latest {
		return fmt.Errorf("%w: database is at version %d, this airlock knows up to %d", ErrSchemaTooNew, current, latest)
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := s.apply(ctx, conn, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) apply(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %d: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback() }()
	// One statement per call, since not every driver runs several in one Exec.
	for _, stmt := range strings.Split(m.sql, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.q("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"), m.version, millis(s.now())); err != nil {
		return fmt.Errorf("migration %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %d: %w", m.version, err)
	}
	return nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func schemaVersion(ctx context.Context, q queryer) (int, error) {
	var v int
	if err := q.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v); err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}
	return v, nil
}

// SchemaVersion returns the database's schema version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	return schemaVersion(ctx, s.db)
}
