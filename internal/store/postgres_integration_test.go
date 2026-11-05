//go:build integration

package store_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/internal/store/storetest"
)

func postgresDSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AIRLOCK_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AIRLOCK_TEST_POSTGRES_DSN is not set")
	}
	return dsn
}

// freshSchema returns a DSN that points at a new, empty schema, dropped after the test.
func freshSchema(t *testing.T) string {
	t.Helper()
	dsn := postgresDSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := strings.ReplaceAll(storetest.NewOrg(t), "-", "_")
	if _, err := db.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}

func TestPostgres(t *testing.T) {
	dsn := freshSchema(t)
	storetest.Run(t, func(t *testing.T) *store.Store {
		st, err := store.Open(context.Background(), "postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	})
}

func TestPostgresConcurrentOpen(t *testing.T) {
	dsn := freshSchema(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			st, err := store.Open(context.Background(), "postgres", dsn)
			if err == nil {
				err = st.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Open: %v", err)
		}
	}
	st, err := store.Open(context.Background(), "postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if v, err := st.SchemaVersion(context.Background()); err != nil || v != store.LatestSchema {
		t.Errorf("SchemaVersion = %d, %v", v, err)
	}
}
