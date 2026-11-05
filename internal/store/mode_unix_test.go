//go:build !windows

package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/raven-clown/airlock/internal/store"
)

func TestSQLiteFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.db")
	st, err := store.Open(context.Background(), "sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.Create(context.Background(), store.DefaultOrg, store.KindRules, "r", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", filepath.Base(p), mode)
		}
	}
}
