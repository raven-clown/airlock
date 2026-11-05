package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/internal/store/storetest"
)

func sqliteDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "airlock.db"))
}

func openSQLite(t *testing.T, dsn string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) *store.Store { return openSQLite(t, sqliteDSN(t)) })
}

func TestReopenKeepsData(t *testing.T) {
	dsn := sqliteDSN(t)
	st, err := store.Open(context.Background(), "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindRules, "r", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st = openSQLite(t, dsn)
	if _, err := st.Get(context.Background(), store.DefaultOrg, store.KindRules, "r"); err != nil {
		t.Errorf("row lost on reopen: %v", err)
	}
	if v, err := st.SchemaVersion(context.Background()); err != nil || v != store.LatestSchema {
		t.Errorf("SchemaVersion = %d, %v, want %d", v, err, store.LatestSchema)
	}
}

func TestSchemaTooNew(t *testing.T) {
	dsn := sqliteDSN(t)
	st := openSQLite(t, dsn)
	if err := st.ExecForTest(context.Background(), "INSERT INTO schema_migrations (version, applied_at) VALUES (999, 0)"); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	_, err := store.Open(context.Background(), "sqlite", dsn)
	if !errors.Is(err, store.ErrSchemaTooNew) || !strings.Contains(err.Error(), "999") {
		t.Errorf("Open error = %v, want ErrSchemaTooNew naming 999", err)
	}
}

func TestWAL(t *testing.T) {
	st := openSQLite(t, sqliteDSN(t))
	mode, err := st.QueryStringForTest(context.Background(), "PRAGMA journal_mode")
	if err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v", mode, err)
	}
}

func TestUnknownDriver(t *testing.T) {
	if _, err := store.Open(context.Background(), "mysql", "x"); err == nil || !strings.Contains(err.Error(), "mysql") {
		t.Errorf("Open(mysql) error = %v", err)
	}
}

func TestPing(t *testing.T) {
	st := openSQLite(t, sqliteDSN(t))
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if err := st.Ping(context.Background()); err == nil {
		t.Error("Ping after Close succeeded")
	}
}
